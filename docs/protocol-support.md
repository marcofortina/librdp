<!--
Copyright (C) 2026 Marco Fortina
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Protocol Support

This document tracks source-tree coverage. "Source complete" means the repository contains the protocol-side implementation, public or internal integration path, and test or fuzz coverage for the current library scope. It does not replace target-specific interoperability validation.

## Core graphics and transport

| Protocol | Area | Source status |
| --- | --- | --- |
| MS-RDPBCGR | Core connection, security negotiation, MCS/GCC, slow path, fast path, activation, input, bitmap updates, orders, and session control | Source complete, target validation required |
| MS-RDPEGFX | Graphics pipeline, surface commands, progressive paths, AVC paths, ClearCodec integration, and capability negotiation | Source complete, target validation required |
| MS-RDPRFX | RemoteFX codec and progressive stream handling | Source complete, target validation required |
| MS-RDPNSC | NSCodec bitmap decoding | Source complete, target validation required |
| MS-RDPEGDI | GDI order parsing and rendering into the surface pipeline | Source complete, target validation required |
| MS-RDPEDISP | Display control and resize layout messaging | Source complete, target validation required |
| MS-RDPEDYC | Dynamic virtual channel transport and channel lifecycle | Source complete, target validation required |
| MS-RDPEMT | Multitransport negotiation and packet handling | Source complete, target validation required |
| MS-RDPEUDP | UDP transport packet handling | Source complete, target validation required |
| MS-RDPEUDP2 | UDP transport v2 packet handling | Source complete, target validation required |

## Input, clipboard, audio, and video

| Protocol | Area | Source status |
| --- | --- | --- |
| MS-RDPECLIP | Clipboard formats, data requests, file contents, and local clipboard publication | Source complete, target validation required |
| MS-RDPEI | Multi-touch and pen input channel messages | Source complete, target validation required |
| MS-RDPECI | Core input channel behavior | Source complete, target validation required |
| MS-RDPEA | Audio output channel behavior | Source complete, target validation required |
| MS-RDPEAI | Audio input channel behavior | Source complete, target validation required |
| MS-RDPEV | Video redirection channel behavior | Source complete, target validation required |
| MS-RDPEVOR | Video optimized remoting behavior | Source complete, target validation required |

## Device, application, and composition channels

| Protocol | Area | Source status |
| --- | --- | --- |
| MS-RDPDR | Device redirection core, device announce, IRP routing, and class dispatch | Source complete, target validation required |
| MS-RDPEFS | Filesystem redirection, metadata, attributes, locking, and file operation classes | Source complete, target validation required |
| MS-RDPESP | Serial and parallel port redirection | Source complete, target validation required |
| MS-RDPEPC | Printer redirection and print job output routing | Source complete, target validation required |
| MS-RDPEUSB | USB redirection packet and backend integration path | Source complete, target validation required |
| MS-RDPEPNP | Plug-and-play device redirection | Source complete, target validation required |
| MS-RDPERP | Remote Programs and RAIL message handling | Source complete, target validation required |
| MS-RDPEXPS | XPS print path support | Source complete, target validation required |
| MS-RDPELE | Licensing exchange behavior | Source complete, target validation required |
| MS-RDPEMC | Multiparty channel behavior | Source complete, target validation required |
| MS-RDPET | Telemetry channel behavior | Source complete, target validation required |
| MS-RDPEAR | Authentication redirection behavior | Source complete, target validation required |
| MS-RDPESC | Smartcard redirection with PC/SC backend integration path | Source complete, target validation required |
| MS-RDPCR2 | Composited remoting and render tree behavior | Source complete, target validation required |
| MS-RDPEDC | Desktop composition channel behavior | Source complete, target validation required |
| MS-RDPEPS | Protocol selection and session selection behavior | Source complete, target validation required |
| MS-RDPECAM | Camera and video capture channel behavior | Source complete, target validation required |
| MS-RDPEECO | Echo diagnostics channel behavior | Source complete, target validation required |
| MS-RDPEWA | WebAuthn redirection behavior | Source complete, target validation required |

## Validation rule

A protocol row can remain source complete only when:

- the implementation path is present in the source tree;
- boundary checks reject malformed input;
- normal and malformed cases are covered by unit tests or fuzz targets;
- tracing exists for negotiation, packet dispatch, and meaningful failures;
- optional backend behavior is documented in [Backends](backends.md).
