<!--
Copyright (C) 2026 Marco Fortina
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Protocol Support

This document maps RDP protocol areas to the implementation and integration scope exposed by the library and viewer.

## Core graphics and transport

| Protocol | Area |
| --- | --- |
| MS-RDPBCGR | Core connection, security negotiation, MCS/GCC, slow path, fast path, activation, input, bitmap updates, orders, and session control |
| MS-RDPEGFX | Graphics pipeline, surface commands, progressive paths, AVC paths, ClearCodec integration, and capability negotiation |
| MS-RDPRFX | RemoteFX codec and progressive stream handling |
| MS-RDPNSC | NSCodec bitmap decoding |
| MS-RDPEGDI | GDI order parsing and rendering into the surface pipeline |
| MS-RDPEDISP | Display control and resize layout messaging |
| MS-RDPEDYC | Dynamic virtual channel transport and channel lifecycle |
| MS-RDPEMT | Multitransport negotiation and packet handling |
| MS-RDPEUDP | UDP transport packet handling |
| MS-RDPEUDP2 | UDP transport v2 packet handling |

## Input, clipboard, audio, and video

| Protocol | Area |
| --- | --- |
| MS-RDPECLIP | Clipboard formats, data requests, file contents, and local clipboard publication |
| MS-RDPEI | Multi-touch and pen input channel messages |
| MS-RDPECI | Core input channel behavior |
| MS-RDPEA | Audio output channel behavior |
| MS-RDPEAI | Audio input channel behavior |
| MS-RDPEV | Video redirection channel behavior |
| MS-RDPEVOR | Video optimized remoting behavior |

## Device, application, and composition channels

| Protocol | Area |
| --- | --- |
| MS-RDPDR | Device redirection core, device announce, IRP routing, and class dispatch |
| MS-RDPEFS | Filesystem redirection, metadata, attributes, locking, and file operation classes |
| MS-RDPESP | Serial and parallel port redirection |
| MS-RDPEPC | Printer redirection and print job output routing |
| MS-RDPEUSB | USB redirection packet and backend integration path |
| MS-RDPEPNP | Plug-and-play device redirection |
| MS-RDPERP | Remote Programs and RAIL message handling |
| MS-RDPEXPS | XPS print path support |
| MS-RDPELE | Licensing exchange behavior |
| MS-RDPEMC | Multiparty channel behavior |
| MS-RDPET | Telemetry channel behavior |
| MS-RDPEAR | Authentication redirection behavior |
| MS-RDPESC | Smartcard redirection with PC/SC backend integration path |
| MS-RDPCR2 | Composited remoting and render tree behavior |
| MS-RDPEDC | Desktop composition channel behavior |
| MS-RDPEPS | Protocol selection and session selection behavior |
| MS-RDPECAM | Camera and video capture channel behavior |
| MS-RDPEECO | Echo diagnostics channel behavior |
| MS-RDPEWA | WebAuthn redirection behavior |

## Coverage rule

A protocol row belongs in this document when:

- the implementation path is present in the source tree;
- boundary checks reject malformed input;
- normal and malformed cases are covered by unit tests or fuzz targets;
- tracing exists for negotiation, packet dispatch, and meaningful failures;
- optional backend behavior is documented in [Backends](backends.md).
