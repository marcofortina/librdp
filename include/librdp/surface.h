/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef LIBRDP_SURFACE_H
#define LIBRDP_SURFACE_H

#include <stddef.h>
#include <stdint.h>

#include <librdp/error.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup librdp_surface Surface API
 * @brief BGRA framebuffer surface allocation, mutation, and access functions.
 * @{
 */

/**
 * @brief Opaque BGRA framebuffer surface.
 *
 * The handle owns its pixel buffer and metadata. It is allocated with
 * librdp_surface_new(), may be resized, and is freed with librdp_surface_free().
 *
 * @since 0.1.0
 */
typedef struct librdp_surface librdp_surface;

/**
 * @brief Pixel format used by librdp_surface.
 *
 * Only BGRA32 is currently exposed through the public surface API.
 *
 * @since 0.1.0
 */
typedef enum librdp_pixel_format
{
    LIBRDP_PIXEL_FORMAT_BGRA32 = 1 /**< Four bytes per pixel in blue, green, red, alpha order. */
} librdp_pixel_format;

/**
 * @brief Allocate a BGRA surface.
 *
 * The returned surface owns a zero-initialized framebuffer with one row per
 * scanline. Width and height must be non-zero and no larger than 8192 pixels;
 * the only implemented pixel format is LIBRDP_PIXEL_FORMAT_BGRA32.
 *
 * @param[in] width Surface width in pixels.
 * @param[in] height Surface height in pixels.
 * @param[in] format Pixel format to allocate.
 *
 * @return Newly allocated surface owned by the caller, or NULL when arguments
 * are invalid or memory cannot be allocated.
 *
 * @note Thread-safety: the returned object is not internally synchronized.
 * Access it from one thread at a time unless the application provides locking.
 * @since 0.1.0
 */
LIBRDP_API librdp_surface* librdp_surface_new(uint32_t width, uint32_t height, librdp_pixel_format format);

/**
 * @brief Free a surface and its framebuffer.
 *
 * Passing NULL is allowed and has no effect. All pixel pointers returned by
 * librdp_surface_pixels() or librdp_surface_pixels_mut() become invalid.
 *
 * @param[in,out] surface Surface to free, or NULL.
 *
 * @note Thread-safety: the caller must ensure no other thread is using the
 * surface while it is being freed.
 * @since 0.1.0
 */
LIBRDP_API void librdp_surface_free(librdp_surface* surface);

/**
 * @brief Replace a surface framebuffer with a new zero-filled size.
 *
 * Existing pixels are discarded on success. Width and height must be non-zero
 * and no larger than 8192 pixels.
 *
 * @param[in,out] surface Surface to resize; must not be NULL.
 * @param[in] width New width in pixels.
 * @param[in] height New height in pixels.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * or invalid dimensions; LIBRDP_STATUS_NO_MEMORY when allocation fails.
 *
 * @note Thread-safety: this mutates the framebuffer and is not internally
 * synchronized.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_surface_resize(librdp_surface* surface, uint32_t width, uint32_t height);

/**
 * @brief Copy a BGRA32 rectangle into a surface.
 *
 * The source buffer is read during the call only and is not retained. The
 * destination rectangle must fit inside the surface and the source stride must
 * be at least width * 4 bytes.
 *
 * @param[in,out] surface Destination surface; must not be NULL.
 * @param[in] x Destination left coordinate in pixels.
 * @param[in] y Destination top coordinate in pixels.
 * @param[in] width Rectangle width in pixels; must be non-zero.
 * @param[in] height Rectangle height in pixels; must be non-zero.
 * @param[in] pixels Source BGRA32 bytes; must not be NULL.
 * @param[in] stride Source row stride in bytes.
 *
 * @return LIBRDP_STATUS_OK on success; LIBRDP_STATUS_INVALID_ARGUMENT for NULL
 * pointers, unsupported surface format, invalid bounds, or too small a stride.
 *
 * @note Thread-safety: this mutates the framebuffer and is not internally
 * synchronized.
 * @since 0.1.0
 */
LIBRDP_API librdp_status librdp_surface_blit_bgra32(librdp_surface* surface,
                                         uint32_t x,
                                         uint32_t y,
                                         uint32_t width,
                                         uint32_t height,
                                         const uint8_t* pixels,
                                         size_t stride);

/**
 * @brief Return the current surface width.
 *
 * @param[in] surface Surface to query, or NULL.
 *
 * @return Width in pixels, or 0 when surface is NULL.
 *
 * @note Thread-safety: concurrent reads are safe only while no other thread
 * mutates or frees the surface.
 * @since 0.1.0
 */
LIBRDP_API uint32_t librdp_surface_width(const librdp_surface* surface);

/**
 * @brief Return the current surface height.
 *
 * @param[in] surface Surface to query, or NULL.
 *
 * @return Height in pixels, or 0 when surface is NULL.
 *
 * @note Thread-safety: concurrent reads are safe only while no other thread
 * mutates or frees the surface.
 * @since 0.1.0
 */
LIBRDP_API uint32_t librdp_surface_height(const librdp_surface* surface);

/**
 * @brief Return the byte stride of a surface row.
 *
 * @param[in] surface Surface to query, or NULL.
 *
 * @return Row stride in bytes, or 0 when surface is NULL.
 *
 * @note Thread-safety: concurrent reads are safe only while no other thread
 * mutates or frees the surface.
 * @since 0.1.0
 */
LIBRDP_API size_t librdp_surface_stride(const librdp_surface* surface);

/**
 * @brief Return the pixel format of a surface.
 *
 * @param[in] surface Surface to query, or NULL.
 *
 * @return Surface pixel format, or 0 when surface is NULL.
 *
 * @note Thread-safety: concurrent reads are safe only while no other thread
 * mutates or frees the surface.
 * @since 0.1.0
 */
LIBRDP_API librdp_pixel_format librdp_surface_format(const librdp_surface* surface);

/**
 * @brief Return a read-only pointer to the framebuffer.
 *
 * The returned pointer is owned by the surface. It remains valid until the
 * surface is resized or freed; for session-owned surfaces it may also change
 * after protocol processing updates the surface storage.
 *
 * @param[in] surface Surface to query, or NULL.
 *
 * @return Read-only framebuffer pointer, or NULL when surface is NULL.
 *
 * @note Thread-safety: the pointer must not be used concurrently with mutation
 * or destruction of the same surface.
 * @since 0.1.0
 */
LIBRDP_API const uint8_t* librdp_surface_pixels(const librdp_surface* surface);

/**
 * @brief Return a writable pointer to the framebuffer.
 *
 * The returned pointer is owned by the surface. It remains valid until the
 * surface is resized or freed. Applications that write through this pointer are
 * responsible for preserving BGRA32 layout and stride boundaries.
 *
 * @param[in,out] surface Surface to query, or NULL.
 *
 * @return Writable framebuffer pointer, or NULL when surface is NULL.
 *
 * @note Thread-safety: the pointer must not be used concurrently with mutation
 * or destruction of the same surface by another thread.
 * @since 0.1.0
 */
LIBRDP_API uint8_t* librdp_surface_pixels_mut(librdp_surface* surface);

/** @} */

#ifdef __cplusplus
}
#endif

#endif
