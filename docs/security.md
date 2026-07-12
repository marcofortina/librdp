<!--
Copyright (C) 2026 Marco Fortina
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Security

librdp processes untrusted network input and sensitive local credentials. Security-sensitive behavior is split between transport security, authentication, parser hardening, trace redaction, and backend boundaries.

## Security modes

Public settings expose:

- `LIBRDP_SECURITY_AUTO`: negotiate the strongest supported mode.
- `LIBRDP_SECURITY_STANDARD`: legacy RDP security.
- `LIBRDP_SECURITY_TLS`: TLS transport security without network-level authentication.
- `LIBRDP_SECURITY_NLA`: network-level authentication through CredSSP.

The X11 viewer exposes these as `auto`, `rdp`, `tls`, and `nla`.

## Credentials

Passwords are copied into settings and session state when configured. They must never be logged, traced, hexdumped, or copied into user-visible error messages.

Applications should free settings and sessions as soon as they are no longer needed. Callers that store credentials outside the library remain responsible for their own memory handling and UI policy.

## Cryptography

Cryptographic primitives are delegated to system libraries where practical. TLS, hashing, signing, and legacy stream cipher behavior use OpenSSL-backed paths. Character conversion uses iconv where available through the configured build.

Security code must not introduce new custom cryptographic primitives when a maintained system library provides the required behavior.

## Network parsing

All transport, protocol, channel, graphics, and codec parsers treat incoming bytes as untrusted. Parser code validates sizes before reads and validates counters before allocation or loops.

Malformed input should return explicit failure status, close the affected session path when needed, and avoid partial state commits.

## Trace safety

Trace output goes to `stderr` and is disabled by default. Trace messages must omit or mask:

- passwords;
- authentication tokens;
- private keys;
- session secrets;
- smartcard PIN-like material;
- WebAuthn assertions when not required for debugging.

Protocol hexdumps are always bounded by `LIBRDP_TRACE_HEX_BYTES` and require protocol tracing at trace level.

## Backend trust boundary

Host devices, local files, printers, cameras, USB devices, smartcards, and authenticators are separate trust domains. Viewer code chooses and opens these resources. The core library receives only the configured public settings and protocol events.

Backends must validate local paths, device selectors, payload lengths, and permissions before advertising capabilities to a remote peer.
