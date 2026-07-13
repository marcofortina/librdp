<!--
Copyright (C) 2026 Marco Fortina
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Backend Guide

Backends adapt host facilities to protocol features without leaking platform handles into the core API. Applications own local device policy, permissions, and user consent. The library owns protocol packet sequencing, negotiated channel state, and event delivery.

Backend configuration starts from public settings in `include/librdp/settings.h`. Runtime investigation uses the structured trace format described in [Tracing](tracing.md).

## Common backend contract

Every backend should follow the same lifecycle:

1. Parse application settings.
2. Probe local dependencies and permissions.
3. Open local handles only after the feature is explicitly configured.
4. Report setup failures through return codes or viewer diagnostics.
5. Keep blocking host operations outside protocol callbacks.
6. Copy or retain event data only when the public API says the application owns it.
7. Close host handles before session teardown completes.

Trace should identify backend name, operation, selector, and failure stage. Trace must not print credentials, authentication assertions, clipboard payloads, file contents, smartcard secrets, audio samples, or camera frames.

## Audio output and input

Backend provider: PipeWire.

Settings and viewer options:

- `LIBRDP_FEATURE_AUDIO_OUTPUT`;
- `LIBRDP_FEATURE_AUDIO_INPUT`;
- `librdp_settings_set_audio_output_device()`;
- `librdp_settings_set_audio_input_device()`;
- `--audio-output [device=name]`;
- `--audio-input [device=name]`.

Operational requirements:

- connect to the user PipeWire session;
- select a format compatible with the server-advertised format list;
- keep stream callbacks bounded;
- queue audio capture data before calling `librdp_session_audio_input_send_data()`;
- stop streams when the corresponding channel closes.

Failure handling:

- missing PipeWire support disables the viewer backend while preserving the core build;
- stream creation failure should produce a client trace event and reject the audio input open request when capture cannot start;
- format mismatch should select another advertised format or report an unsupported backend condition.

Useful trace families:

- `client.rdpsnd.*`;
- `client.audin.*`;
- `x11.audio.*`.

## Camera and video

Backend providers: V4L2 camera input and file video sink.

Settings and viewer options:

- `LIBRDP_FEATURE_CAMERA`;
- `LIBRDP_FEATURE_VIDEO`;
- `librdp_settings_add_camera()`;
- `librdp_settings_set_video_output()`;
- `--camera device=/dev/videoN`;
- `--video [file=path]`.

Operational requirements:

- open the camera device after feature configuration;
- enumerate or validate media formats before accepting capture requests;
- convert or reject unsupported server-requested formats explicitly;
- reply to sample requests with `librdp_session_video_capture_send_sample()` or `librdp_session_video_capture_send_error()`;
- avoid dumping frame payloads in trace.

Failure handling:

- device open failure should keep the session alive and report capture unavailable;
- media format mismatch should send a video capture error rather than returning malformed data;
- file sink write failure should close the sink and trace the failing operation.

Useful trace families:

- `client.video.*`;
- `client.camera.*`;
- `x11.camera.*`.

## Smartcard

Backend providers: PC/SC and controlled virtual smartcard source.

Settings and viewer options:

- `LIBRDP_FEATURE_SMARTCARD`;
- `librdp_settings_add_smartcard()`;
- `--smartcard [pcsc|vsmartcard=path]`.

Operational requirements:

- create the PC/SC context in the backend;
- preserve APDU request ordering;
- map card presence and removal to channel state;
- keep APDU buffers bounded and copied according to channel ownership;
- close card handles before backend teardown.

Failure handling:

- missing PC/SC support disables the PC/SC backend;
- absent card should be reported as device unavailable, not as a parser failure;
- APDU transport failure should complete the pending request with an explicit failure status.

Useful trace families:

- `client.rdpdr.*`;
- `client.smartcard.*`;
- `x11.smartcard.*`.

## USB and PNP

Backend providers: libusb for USB and host device descriptors for PNP.

Settings and viewer options:

- `LIBRDP_FEATURE_USB`;
- `LIBRDP_FEATURE_PNP`;
- `librdp_settings_add_usb_device()`;
- `librdp_settings_add_pnp_device()`;
- `--usb vid:pid`;
- `--usb bus:dev`;
- `--pnp`.

Operational requirements:

- validate selectors before advertisement;
- never auto-announce local host devices from viewer-side discovery;
- claim only explicitly configured devices;
- map transfer completion to the matching outstanding request;
- handle detach while requests are pending;
- keep host permissions and device ownership outside core protocol code.

Failure handling:

- permission denied should produce a backend failure, not a channel parser failure;
- device detach should complete or cancel outstanding operations in order;
- unsupported transfer types should be rejected with a protocol-visible error.

Useful trace families:

- `client.rdpdr.*`;
- `client.urbdrc.*`;
- `x11.usb.*`;
- `client.pnp.*`.

## Filesystem

Backend providers: host filesystem, `libacl`, `libattr`, and `libarchive` where available.

Settings and viewer options:

- `librdp_settings_add_drive()`;
- `--drive name=path`.

Operational requirements:

- expose only configured roots;
- normalize host paths before access;
- reject traversal outside the configured root;
- map file IDs to open host handles;
- implement metadata, directory enumeration, locking, notification, and range operations according to local capability;
- translate host errors to protocol-visible statuses without exposing private paths unnecessarily.

Failure handling:

- missing ACL or xattr support should degrade metadata fidelity while keeping ordinary file I/O available;
- archive extraction must stay bounded by configured roots and size policy;
- stale handles should fail the request and clear the mapping.

Useful trace families:

- `client.rdpdr.*`;
- `client.rdpefs.*`;
- `client.filesystem.*`.

## Serial and parallel ports

Backend providers: host character devices and file-like output paths.

Settings and viewer options:

- `librdp_settings_add_serial_port()`;
- `librdp_settings_add_parallel_port()`;
- `--serial name=path`;
- `--parallel name=path`.

Operational requirements:

- open configured paths only after explicit selection;
- preserve read/write ordering;
- report unsupported control operations explicitly;
- close host descriptors on channel removal.

Failure handling:

- permission and open failures should mark the device unavailable;
- unsupported modem or line-control operations should not corrupt the request stream;
- partial writes should be reported with the completed byte count where the protocol path supports it.

Useful trace families:

- `client.rdpdr.*`;
- `client.serial.*`;
- `client.parallel.*`.

## Printer and XPS

Backend providers: CUPS and file output path.

Settings and viewer options:

- `librdp_settings_add_printer()`;
- `--printer name=driver=path`.

Operational requirements:

- create jobs only for configured printers;
- preserve job, page, and data chunk ordering;
- close or cancel jobs on disconnect;
- keep spool files bounded by application policy;
- expose printer errors through device responses and client trace.

Failure handling:

- unavailable CUPS should keep file output usable when configured;
- backend write failure should fail the current job and close local resources;
- unsupported printer capabilities should be omitted from advertisement rather than accepted and ignored.

Useful trace families:

- `client.rdpdr.*`;
- `client.printer.*`;
- `client.xps.*`.

## Clipboard

Backend provider: application clipboard integration.

Public APIs:

- `librdp_session_clipboard_set_data()`;
- `librdp_session_clipboard_set_files()`;
- `librdp_session_clipboard_request_data()`;
- `librdp_session_clipboard_request_file_size()`;
- `librdp_session_clipboard_request_file_range()`.

Operational requirements:

- publish only user-approved formats;
- copy borrowed event data before returning from callbacks;
- bound file transfer range sizes;
- clear local clipboard state when the application policy requires it.

Failure handling:

- unknown formats should remain requestable only if the application can supply bytes;
- missing file paths should fail the request and clear stale metadata;
- oversized payloads should be rejected before allocation.

Useful trace families:

- `client.clipboard.*`;
- `client.channel.*`.

## WebAuthn

Backend providers: libfido2, hidraw selector, or controlled mock provider.

Settings and viewer options:

- `LIBRDP_FEATURE_WEBAUTHN`;
- `librdp_settings_set_webauthn_provider()`;
- `--webauthn [fido2|fido2=/dev/hidrawN|mock|mock=path]`.

Operational requirements:

- preserve user-presence policy in the backend;
- never trace assertion secrets or credential IDs in full;
- handle cancellation and timeout paths;
- map authenticator status to channel responses.

Failure handling:

- missing authenticator should return an explicit provider error;
- denied user presence should not be retried silently;
- malformed requests should be rejected before reaching the authenticator.

Useful trace families:

- `client.webauthn.*`;
- `x11.webauthn.*`.

## Remote applications, composition, echo, telemetry, and multitransport

Settings and viewer options:

- `LIBRDP_FEATURE_RAIL`;
- `LIBRDP_FEATURE_CR2`;
- `LIBRDP_FEATURE_DESKTOP_COMPOSITION`;
- `LIBRDP_FEATURE_ECHO`;
- `LIBRDP_FEATURE_TELEMETRY`;
- `LIBRDP_FEATURE_MULTITRANSPORT`;
- `--rail app=path`;
- `--cr2`;
- `--echo`;
- `--telemetry`;
- `--multitransport`.

Operational requirements:

- keep application lifecycle events serialized with session processing;
- keep compositor tree ownership in the graphics/composition path;
- keep echo responses bounded by the channel payload limits;
- keep telemetry metadata free of private content when a telemetry runtime is registered;
- keep multitransport capability negotiation disabled unless a side-transport runtime is registered.

Failure handling:

- remote application failures should surface as application lifecycle events;
- compositor object loss should invalidate dependent visual state;
- side-transport runtime failures should not corrupt the primary transport state.

Useful trace families:

- `client.rail.*`;
- `client.cr2.*`;
- `client.echo.*`;
- `client.telemetry.*`;
- `transport.udp.*`;
- `transport.multitransport.*`.
