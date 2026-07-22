/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: Cocoa viewer pasteboard bridge declarations.
 * Invariants: one remote format or file range is pending at a time, local and
 * remote ownership changes do not echo, and payloads stay within fixed quotas.
 * Ownership: callback inputs are borrowed for each call; the bridge owns copied
 * remote metadata and temporary downloaded files until shutdown or replacement.
 * Threading: every method runs on the AppKit/session owner thread.
 * Trust boundary: native pasteboard objects and remote clipboard payloads are
 * validated before protocol publication or filesystem access.
 */

#ifndef LIBRDP_COCOA_VIEWER_CLIPBOARD_H
#define LIBRDP_COCOA_VIEWER_CLIPBOARD_H

#import <Cocoa/Cocoa.h>

#include <librdp/librdp.h>

typedef struct cocoa_viewer_clipboard_callbacks
{
    librdp_status (*set_data)(void* context,
                              uint32_t format_id,
                              const void* data,
                              size_t data_len);
    librdp_status (*set_named_data)(void* context,
                                    uint32_t format_id,
                                    const char* format_name,
                                    const void* data,
                                    size_t data_len);
    librdp_status (*set_files)(void* context,
                               const librdp_clipboard_file* files,
                               uint32_t count);
    librdp_status (*clear)(void* context);
    librdp_status (*request_data)(void* context,
                                  uint32_t format_id);
    librdp_status (*request_file_range)(void* context,
                                        uint32_t stream_id,
                                        int32_t file_index,
                                        uint64_t position,
                                        uint32_t requested);
    double (*now)(void* context);
} cocoa_viewer_clipboard_callbacks;

typedef struct cocoa_viewer_clipboard_state
    cocoa_viewer_clipboard_state;

@interface CocoaViewerClipboard : NSObject
{
    NSPasteboard* _pasteboard;
    cocoa_viewer_clipboard_state* _state;
}

- (id)initWithSession:(librdp_session*)session;
- (id)initWithPasteboard:(NSPasteboard*)pasteboard
                callbacks:(const cocoa_viewer_clipboard_callbacks*)callbacks
                  context:(void*)context;
- (librdp_status)poll;
- (librdp_status)handleEnvelope:(const librdp_event_envelope*)envelope;
- (void)shutdown;

@end

#endif
