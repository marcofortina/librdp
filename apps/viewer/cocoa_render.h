/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: Cocoa viewer surface presentation boundary.
 * Invariants: rendering borrows one read mapping at a time and accepts only
 * BGRA32 surfaces with validated dimensions and stride.
 * Ownership: CoreGraphics objects are released before the surface is unmapped;
 * neither the context nor framebuffer bytes are retained.
 * Threading: callers serialize rendering on the AppKit event thread.
 * Trust boundary: remote dimensions and framebuffer metadata are checked
 * before CoreGraphics receives them.
 */

#ifndef LIBRDP_COCOA_VIEWER_RENDER_H
#define LIBRDP_COCOA_VIEWER_RENDER_H

#include <CoreGraphics/CoreGraphics.h>

#include <librdp/surface.h>

/*
 * Draw one public BGRA surface into the supplied CoreGraphics destination.
 * The context and surface remain caller-owned and no mapping survives return.
 */
librdp_status cocoa_render_surface(CGContextRef context,
                                   librdp_surface* surface,
                                   CGRect destination);

#endif
