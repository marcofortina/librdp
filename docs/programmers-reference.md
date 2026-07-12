<!--
Copyright (C) 2026 Marco Fortina
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Programmer's Reference Manual

This manual describes how to build an application on top of librdp. It complements the API reference and examples.

## Application responsibilities

An application owns:

- UI and event loop integration;
- credential collection and storage policy;
- local input translation;
- surface presentation;
- clipboard policy;
- local device and backend selection;
- user-visible error reporting;
- session retry or reconnect policy.

The library owns protocol sequencing, transport state, security negotiation, graphics decoding, channel dispatch, and event delivery.

## Session driver model

Applications drive a session by calling `librdp_session_run_once()` from a serialized loop. The loop usually multiplexes local UI events and session I/O:

1. Process pending local UI events.
2. Send input or local feature responses.
3. Call `librdp_session_run_once()` with a bounded timeout.
4. Present dirty surface rectangles delivered by callbacks.
5. Exit the loop on disconnect, fatal status, or application shutdown.

Do not call session APIs concurrently from multiple threads unless the application provides external locking.

## Callback model

Events are synchronous. A callback runs from the API call or run loop that produced the event. Keep callback work bounded:

- copy borrowed bytes if they must be retained;
- enqueue expensive UI work to the application loop;
- avoid recursive session-driving calls from inside callbacks;
- avoid blocking on host devices from inside protocol dispatch.

## Building a viewer

A viewer normally needs:

- a settings builder;
- a session object;
- an event callback;
- a local window and framebuffer presenter;
- keyboard and pointer translation;
- cursor shape handling;
- resize handling;
- optional clipboard, audio, video, and device backends.

The X11 viewer demonstrates these pieces while keeping X11 and backend dependencies outside the core.

## Surface presentation strategy

Use `LIBRDP_EVENT_SURFACE_INVALIDATED` to identify dirty rectangles. Present only dirty rectangles when the local UI toolkit supports it. Present the full surface after local expose events, resize, reconnect, or when the UI backend loses damage history.

The session-owned surface remains borrowed. Do not store pixel pointers across session calls that may update or resize the surface.

## Keyboard and pointer strategy

Use the host input stack for layout, modifiers, composed text, and dead keys. Translate into RDP scancodes, flags, Unicode fallback, and pointer coordinates before calling session input APIs.

For keyboard grabs, release remote pressed keys when focus is lost. Avoid releasing the local grab while remote modifiers are still pressed.

Pointer shape is server-driven. Apply pointer events from the session rather than guessing cursor shape from local coordinates.

## Clipboard strategy

Clipboard integration is policy-heavy. Applications should decide:

- which local formats to publish;
- when to request remote formats;
- whether to allow file transfer;
- how large clipboard payloads may be;
- how long copied data remains in memory.

Borrowed clipboard event data must be copied before the callback returns.

## Audio, video, and camera strategy

Audio output, audio input, video output, and camera capture are event-driven and backend-owned. The library exposes protocol events and response APIs; the application owns the host media device.

Avoid blocking media device operations inside protocol callbacks. Prefer queueing to a backend thread or non-blocking backend loop.

## Device strategy

Device redirection is authority transfer. Applications should require explicit local configuration for drives, ports, printers, smartcards, USB, PNP, and WebAuthn.

Backends should validate local selectors before enabling protocol capabilities. Missing local providers should fail closed and report traceable setup failure.

## Error strategy

Treat public API return codes and asynchronous error events as separate signals:

- immediate return codes describe the call just made;
- error events describe session-level or protocol-level failures;
- disconnect events describe closure.

Applications should not expose raw protocol payloads in user-visible errors.

## Trace strategy

Enable only the trace categories needed for the issue being investigated. Use bounded hexdumps and avoid collecting sensitive application data.

Trace event names are stable enough for filtering and automation. Prefer filtering by category and event prefix.

## Extending an application

When adding a new feature to an application:

1. Add public settings or use existing settings.
2. Register event handling for the corresponding channel or media request.
3. Add host backend probing and failure reporting.
4. Add trace around backend setup and failure.
5. Add unit tests or controlled backend tests for application logic.
6. Update application documentation and CLI help.
