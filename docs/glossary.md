<!--
Copyright (C) 2026 Marco Fortina
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Glossary

This glossary defines terms used by the public API, backend documentation, protocol documentation, and trace output.

| Term | Meaning |
| --- | --- |
| Activation | Session phase where the server and client establish share state, capabilities, and update/input readiness. |
| Backend | Application or viewer-owned adapter for host facilities such as audio, camera, smartcard, USB, filesystem, printer, or authenticator access. |
| Borrowed pointer | Pointer owned by the library or caller for a documented lifetime. Borrowed event payloads expire when the callback returns. |
| Capability | Negotiated feature descriptor exchanged during connection, activation, channel setup, or graphics setup. |
| Channel | Logical protocol stream carried inside the session. Channels may be static, dynamic, or internal to a feature module. |
| Clipboard format | Numeric or named data representation advertised through clipboard integration. |
| Device redirection | Protocol family that exposes configured local devices or resources to the remote session. |
| Dirty rectangle | Surface region changed by a graphics update and delivered to applications through a surface invalidation event. |
| Dynamic virtual channel | Channel created after dynamic channel negotiation and addressed through a runtime channel identifier. |
| Fast-path | Compact RDP update or input transport path used after negotiation. |
| Feature flag | Public settings bit that asks the session to enable a protocol or backend-facing feature. |
| Framebuffer | Pixel storage owned by `librdp_surface` or by the active session surface. |
| Host resource | Local file, device, stream, authenticator, printer, clipboard, or window-system object controlled by the application environment. |
| Invalidated surface | Surface with at least one dirty rectangle that the viewer should repaint. |
| NLA | Network-level authentication path selected by `LIBRDP_SECURITY_NLA`. |
| Opaque handle | Public pointer type whose internal representation is hidden from applications. |
| PDU | Protocol data unit parsed or emitted by transport, security, protocol, graphics, or channel modules. |
| Pointer cache | Session cache of cursor shapes indexed by server-provided cache identifiers. |
| Primary surface | Main remote desktop framebuffer exposed through `librdp_session_get_surface()`. |
| RAIL | Remote application integration path configured through remote application settings. |
| Scancode | Keyboard code sent to the remote session after platform input translation. |
| Serialized context | Application-controlled execution model where calls operating on one session are not concurrent. |
| Slow-path | General RDP PDU path used for connection, control, and some update/input messages. |
| Trace family | Stable event-name prefix used to filter structured runtime trace lines. |
| Trust boundary | Point where data or authority crosses between remote protocol input, library state, application policy, and host resources. |
