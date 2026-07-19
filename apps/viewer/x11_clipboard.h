/*
 * Copyright (C) 2026 Marco Fortina
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Module: X11 clipboard bridge declarations for the viewer.
 * Invariants: local X11 ownership and remote clipboard data are serialized
 * through the viewer event loop.
 * Ownership: copied remote UTF-8 data and optional local file paths are owned
 * by the viewer context.
 * Threading: all entry points are called from the viewer event thread.
 * Trust boundary: X11 selection data and remote clipboard PDUs are untrusted
 * and must be length-checked before conversion or publication.
 */

#ifndef LIBRDP_X11_VIEWER_CLIPBOARD_H
#define LIBRDP_X11_VIEWER_CLIPBOARD_H

#include "x11_app.h"

#include <stddef.h>
#include <stdint.h>

#define X11_CLIPBOARD_REMOTE_KIND_NONE 0u
#define X11_CLIPBOARD_REMOTE_KIND_TEXT 1u
#define X11_CLIPBOARD_REMOTE_KIND_HTML 2u
#define X11_CLIPBOARD_REMOTE_KIND_PNG 3u

void x11_clipboard_init(x11_app* app);
void x11_clipboard_free(x11_app* app);
void x11_clipboard_handle_owner_notify(x11_app* app, XEvent* event);
void x11_clipboard_handle_selection_notify(x11_app* app, XSelectionEvent* selection);
void x11_clipboard_handle_selection_request(x11_app* app, XSelectionRequestEvent* request);
void x11_clipboard_handle_selection_clear(x11_app* app, const XSelectionClearEvent* event);
void x11_clipboard_handle_property_notify(x11_app* app, const XPropertyEvent* event);
void x11_clipboard_check_timeouts(x11_app* app);
int x11_clipboard_next_timeout_ms(const x11_app* app, int* timeout_ms);
void x11_clipboard_clear_remote(x11_app* app);
void x11_clipboard_set_remote_utf16le(x11_app* app, const uint8_t* data, size_t length);
void x11_clipboard_set_remote_html(x11_app* app, const uint8_t* data, size_t length);
void x11_clipboard_set_remote_png(x11_app* app, const uint8_t* data, size_t length);
uint32_t x11_clipboard_choose_remote_format(const librdp_clipboard_format* formats,
                                            uint32_t count,
                                            uint32_t* kind);
int x11_clipboard_accumulate_incr_chunk(uint8_t** buffer,
                                        size_t* length,
                                        size_t* capacity,
                                        const uint8_t* chunk,
                                        size_t chunk_len,
                                        size_t limit);
size_t x11_clipboard_next_incr_chunk_size(size_t total, size_t offset, size_t chunk_limit);
int x11_clipboard_incr_timed_out(uint64_t now_ms, uint64_t deadline_ms);
int x11_clipboard_build_html_format(const uint8_t* html, size_t html_len, uint8_t** out, size_t* out_len);
int x11_clipboard_parse_html_offset(const uint8_t* data,
                                    size_t data_len,
                                    const char* key,
                                    size_t* value);
int x11_clipboard_extract_html_fragment(const uint8_t* data,
                                        size_t data_len,
                                        const uint8_t** fragment,
                                        size_t* fragment_len);
int x11_clipboard_parse_uri_list(const uint8_t* data,
                                 size_t data_len,
                                 librdp_clipboard_file* files,
                                 char** paths,
                                 size_t max_files,
                                 uint32_t* count);
void x11_clipboard_free_uri_paths(char** paths, size_t count);

#endif
