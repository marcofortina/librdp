<!--
Copyright (C) 2026 Marco Fortina
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Protocol Support

This document maps RDP protocol areas to implementation modules, public surfaces, host backends, and parser or codec test entry points.

Rows describe behavior ownership, not release status. A protocol appears here when it has source modules, packet-facing tests or fuzz targets, and a documented public API or backend integration point.

## Core, graphics, and transport

| Protocol | Area | Modules | Tests and fuzz targets |
| --- | --- | --- | --- |
| MS-RDPBCGR | Connection sequence, security negotiation, MCS/GCC, slow path, fast path, activation, input, bitmap updates, orders, and session control | `src/client/session.c`, `src/protocol/*`, `src/security/*`, `src/transport/*`, `src/licensing/licensing.c` | `tests/test_protocol.c`, `tests/test_transport.c`, `fuzz/x224_fuzzer.c`, `fuzz/mcs_fuzzer.c`, `fuzz/gcc_fuzzer.c`, `fuzz/fastpath_fuzzer.c`, `fuzz/slowpath_fuzzer.c`, `fuzz/security_fuzzer.c`, `fuzz/licensing_fuzzer.c` |
| MS-RDPEGFX | Graphics pipeline, surface commands, AVC paths, ClearCodec integration, and graphics capabilities | `src/channels/graphics_pipeline.c`, `src/graphics/surface_commands.c`, `src/graphics/avc.c`, `src/graphics/clearcodec.c` | `tests/test_protocol.c`, `fuzz/graphics_pipeline_fuzzer.c`, `fuzz/surface_commands_fuzzer.c`, `fuzz/avc_fuzzer.c`, `fuzz/clearcodec_fuzzer.c` |
| MS-RDPRFX | RemoteFX codec and stream handling | `src/graphics/rfx_codec.c`, `src/graphics/rfx_stream.c` | `tests/test_protocol.c`, `fuzz/rfx_codec_fuzzer.c`, `fuzz/rfx_stream_fuzzer.c` |
| MS-RDPNSC | NSCodec bitmap decoding | `src/graphics/nscodec.c` | `tests/test_protocol.c`, `fuzz/nscodec_fuzzer.c` |
| MS-RDPEGDI | GDI order parsing and rendering into the surface pipeline | `src/graphics/gdi_orders.c`, `src/graphics/gdi_render.c` | `tests/test_protocol.c`, `fuzz/gdi_orders_fuzzer.c` |
| MS-RDPEDISP | Display control and resize layout messaging | `src/channels/display_control.c`, `src/client/session.c` | `tests/test_protocol.c`, `fuzz/display_control_fuzzer.c` |
| MS-RDPEMT | Multitransport negotiation and packet handling | `src/transport/multitransport.c` | `tests/test_transport.c`, `fuzz/multitransport_fuzzer.c` |
| MS-RDPEUDP | UDP transport packet handling | `src/transport/udp_transport.c` | `tests/test_transport.c`, `fuzz/udp_transport_fuzzer.c` |
| MS-RDPEUDP2 | UDP transport v2 packet handling | `src/transport/udp_transport.c` | `tests/test_transport.c`, `fuzz/udp_transport_fuzzer.c` |

## Channels

| Protocol | Area | Modules | Public surface or backend |
| --- | --- | --- | --- |
| MS-RDPEDYC | Dynamic virtual channel transport and channel lifecycle | `src/channels/dynamic_channel.c`, `src/channels/virtual_channel.c` | `include/librdp/channel.h`, `fuzz/dynamic_channel_fuzzer.c`, `fuzz/virtual_channel_fuzzer.c` |
| MS-RDPECLIP | Clipboard formats, data requests, file contents, and local clipboard publication | `src/clipboard/clipboard.c`, `src/client/session.c` | `include/librdp/clipboard.h`, `fuzz/clipboard_fuzzer.c` |
| MS-RDPEECO | Echo diagnostics channel behavior | `src/channels/echo_channel.c` | `LIBRDP_FEATURE_ECHO`, `fuzz/echo_channel_fuzzer.c` |
| MS-RDPET | Telemetry packet parsing and serialization | `src/channels/telemetry.c` | `LIBRDP_FEATURE_TELEMETRY`, `fuzz/telemetry_fuzzer.c` |
| MS-RDPEMC | Multiparty channel behavior | `src/channels/multiparty.c` | `fuzz/multiparty_fuzzer.c` |

## Public behavior map

| Protocol family | Public API or viewer surface | Primary events | Trace families |
| --- | --- | --- | --- |
| Connection, security, activation | `librdp_settings_*`, `librdp_session_connect()`, `librdp_session_run_once()` | state, error, disconnected | `client.connect.*`, `transport.*`, `x224.*`, `mcs.*`, `rdp.activation.*` |
| Graphics and surfaces | `librdp_session_get_surface()`, `librdp_surface_*` | surface invalidation, error | `rdp.fastpath.*`, `rdp.slowpath.*`, `rdp.gfx.*`, `client.active.framebuffer.*` |
| Pointer | event callback pointer payloads, X11 viewer cursor path | pointer default, hidden, position, shape | `client.pointer.*`, `x11.pointer.*` |
| Keyboard and pointer input | `librdp_session_send_key()`, `librdp_session_send_mouse()` | sent input, error | `client.input.*`, `x11.keyboard.*`, `x11.pointer.*` |
| Touch and pen input | `librdp_session_send_touch()`, `librdp_session_send_pen()` | sent input, error | `client.input.*`, `client.core_input.*` |
| Clipboard | `librdp_session_clipboard_*` | format list, data, request, file contents | `client.clipboard.*`, `client.drdynvc.*` |
| Dynamic channels | `librdp_session_channel_send()`, `librdp_session_channel_close()` | channel open, data, close | `client.channel.*`, `client.drdynvc.*` |
| Device redirection | settings device APIs and viewer backend options | backend errors, device events | `client.rdpdr.*`, device-specific client trace |
| Audio, video, camera | audio/video public response APIs and viewer backend options | audio formats, audio data, capture request | `client.rdpsnd.*`, `client.audin.*`, `client.video.*`, `client.camera.*` |
| Display control | `librdp_session_resize()`, `librdp_session_set_display_layout()` | surface invalidation, state, error | `client.display_control.*`, `client.active.framebuffer.*` |

## Input, audio, and video

| Protocol | Area | Modules | Public surface or backend |
| --- | --- | --- | --- |
| MS-RDPEI | Multi-touch and pen input channel messages | `src/channels/input_channel.c`, `src/input/input.c` | `include/librdp/input.h`, `fuzz/input_channel_fuzzer.c` |
| MS-RDPECI | Core input channel behavior | `src/channels/core_input.c`, `src/input/input.c` | `include/librdp/input.h`, `fuzz/core_input_fuzzer.c` |
| MS-RDPEA | Audio output channel behavior | `src/channels/audio_output.c`, `src/channels/audio_format.c` | `include/librdp/audio.h`, PipeWire viewer backend, `fuzz/audio_output_fuzzer.c`, `fuzz/audio_format_fuzzer.c` |
| MS-RDPEAI | Audio input channel behavior | `src/channels/audio_input.c`, `src/channels/audio_format.c` | `include/librdp/audio.h`, PipeWire viewer backend, `fuzz/audio_input_fuzzer.c`, `fuzz/audio_format_fuzzer.c` |
| MS-RDPEV | Video redirection channel behavior | `src/channels/video_redirection.c` | `include/librdp/video.h`, file sink path, `fuzz/video_redirection_fuzzer.c` |
| MS-RDPEVOR | Video optimized remoting behavior | `src/channels/video_optimized.c` | `include/librdp/video.h`, file sink path, `fuzz/video_optimized_fuzzer.c` |
| MS-RDPECAM | Camera and video capture channel behavior | `src/channels/video_capture.c` | V4L2 viewer backend, `fuzz/video_capture_fuzzer.c` |

## Device, application, and composition

| Protocol | Area | Modules | Public surface or backend |
| --- | --- | --- | --- |
| MS-RDPDR | Device redirection core, device announce, IRP routing, and class dispatch | `src/channels/device_redirection.c` | `include/librdp/settings.h`, `fuzz/device_redirection_fuzzer.c` |
| MS-RDPEFS | Filesystem redirection, metadata, attributes, locking, and file operation classes | `src/channels/filesystem_redirection.c` | `librdp_settings_add_drive()`, libacl/libattr/libarchive paths, `fuzz/filesystem_redirection_fuzzer.c` |
| MS-RDPESP | Serial and parallel port redirection | `src/channels/port_redirection.c` | `librdp_settings_add_serial_port()`, `librdp_settings_add_parallel_port()`, `fuzz/port_redirection_fuzzer.c` |
| MS-RDPEPC | Printer redirection and print job output routing | `src/channels/printer_redirection.c` | `librdp_settings_add_printer()`, CUPS or file output path, `fuzz/printer_redirection_fuzzer.c` |
| MS-RDPEXPS | XPS print path support | `src/channels/xps_print.c` | Printer backend, `fuzz/xps_print_fuzzer.c` |
| MS-RDPEUSB | USB redirection packet and backend integration path | `src/channels/usb_redirection.c` | `librdp_settings_add_usb_device()`, libusb path, `fuzz/usb_redirection_fuzzer.c` |
| MS-RDPEPNP | Plug-and-play device redirection | `src/channels/pnp_redirection.c` | `librdp_settings_add_pnp_device()`, `fuzz/pnp_redirection_fuzzer.c` |
| MS-RDPERP | Remote Programs and RAIL message handling | `src/channels/remote_programs.c` | `librdp_settings_add_rail_app()`, `fuzz/remote_programs_fuzzer.c` |
| MS-RDPELE | Licensing exchange behavior | `src/licensing/licensing.c` | Session negotiation path, `fuzz/licensing_fuzzer.c` |
| MS-RDPEAR | Authentication redirection behavior | `src/channels/auth_redirection.c` | `fuzz/auth_redirection_fuzzer.c` |
| MS-RDPESC | Smartcard redirection with PC/SC backend integration path | `src/channels/smartcard_redirection.c` | `librdp_settings_add_smartcard()`, PC/SC or controlled virtual source, `fuzz/smartcard_redirection_fuzzer.c` |
| MS-RDPCR2 | Composited remoting and render tree behavior | `src/channels/composited_remoting.c` | `LIBRDP_FEATURE_CR2`, `fuzz/composited_remoting_fuzzer.c` |
| MS-RDPEDC | Desktop composition channel behavior | `src/channels/desktop_composition.c` | `LIBRDP_FEATURE_DESKTOP_COMPOSITION`, `fuzz/desktop_composition_fuzzer.c` |
| MS-RDPEPS | Protocol selection and session selection behavior | `src/protocol/session_selection.c` | Connection negotiation path, `fuzz/session_selection_fuzzer.c` |
| MS-RDPEWA | WebAuthn redirection behavior | `src/channels/webauthn_channel.c` | `librdp_settings_set_webauthn_provider()`, libfido2 or controlled mock provider, `fuzz/webauthn_channel_fuzzer.c` |

## Row rule

A protocol row belongs in this document when:

- the packet or channel path has a named module;
- malformed input is routed through bounded parser, decoder, or dispatcher logic;
- unit tests or fuzz targets exercise the packet-facing behavior;
- optional backend behavior is documented in [Backends](backends.md).
