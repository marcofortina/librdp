<!--
Copyright (C) 2026 Marco Fortina
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Security

librdp processes untrusted network input and sensitive local credentials. Security-sensitive behavior is split between transport security, authentication, parser hardening, trace redaction, and backend boundaries.

## Threat model

The remote peer controls network bytes, negotiated capabilities, channel payloads, graphics payloads, clipboard data, and device requests. Local users and applications control settings, credentials, device selectors, filesystem paths, and viewer policy.

The library is responsible for:

- rejecting malformed or inconsistent protocol input;
- bounding all allocation and copy decisions;
- preserving session state invariants after parser failure;
- preventing credential and secret disclosure through trace or errors;
- exposing enough structured status for applications to close or recover a session.

Applications are responsible for:

- deciding which remote host to trust;
- collecting and storing credentials;
- selecting local devices and files;
- enforcing user consent for audio, camera, smartcard, USB, WebAuthn, and clipboard;
- presenting security errors to users.

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

Credential-bearing APIs must treat `NULL` and empty strings exactly as documented in the public headers. Optional username and domain values may be cleared; target and port configuration must remain explicit and valid before connecting.

## Cryptography

Cryptographic primitives are delegated to system libraries where practical. TLS, hashing, signing, and legacy stream cipher behavior use OpenSSL-backed paths. Character conversion uses iconv where available through the configured build.

Security code must not introduce new custom cryptographic primitives when a maintained system library provides the required behavior.

New security code should prefer provider-backed or OS-maintained implementations for:

- TLS and certificate parsing;
- hash and message authentication functions;
- stream or block ciphers;
- ASN.1 and DER primitives;
- Unicode conversion;
- secure random bytes.

Protocol glue may still be implemented in the library when the wire protocol requires custom sequencing, message framing, or state-machine integration.

## Network parsing

All transport, protocol, channel, graphics, and codec parsers treat incoming bytes as untrusted. Parser code validates sizes before reads and validates counters before allocation or loops.

Malformed input should return explicit failure status, close the affected session path when needed, and avoid partial state commits.

Parser and decoder code should follow these rules:

- never trust length fields until the containing buffer has been checked;
- validate multiplication before computing allocation sizes;
- cap counters before loops;
- reject trailing data when the protocol requires exact consumption;
- avoid retaining borrowed transport buffers beyond dispatch;
- normalize parser output before it reaches rendering, input, or backend code.

Graphics decoders must clip to the destination surface before writing pixels. Channel handlers must validate fragmentation state before combining payloads.

## Trace safety

Trace output goes to `stderr` and is disabled by default. Trace messages must omit or mask:

- passwords;
- authentication tokens;
- private keys;
- session secrets;
- smartcard PIN-like material;
- WebAuthn assertions when not required for debugging.

Protocol hexdumps are always bounded by `LIBRDP_TRACE_HEX_BYTES` and require protocol tracing at trace level.

Trace fields should prefer identifiers, sizes, result codes, negotiated flags, and timing data. Payload bytes should be emitted only through the bounded protocol hexdump path. Application data such as clipboard contents, file contents, audio samples, video frames, and authenticator responses should not be dumped.

## Backend trust boundary

Host devices, local files, printers, cameras, USB devices, smartcards, and authenticators are separate trust domains. Viewer code chooses and opens these resources. The core library receives only the configured public settings and protocol events.

Backends must validate local paths, device selectors, payload lengths, and permissions before advertising capabilities to a remote peer.

Backend code should fail closed when a local resource cannot be opened, probed, or mapped safely. A backend failure should not expose a partially initialized device to the remote peer.

## Sensitive feature policy

Clipboard, filesystem, printer, audio, camera, smartcard, USB, and WebAuthn features can move user data or device authority across the session. Applications should expose these features as explicit user choices.

When adding a sensitive feature:

- define the local trust boundary;
- document ownership of local handles;
- identify which payloads are sensitive;
- add trace events for setup and failure without dumping secrets;
- add malformed-packet coverage before routing requests to host resources.

## Certificate and authentication errors

Certificate and authentication failures should return explicit status and trace the failure stage without printing secrets. Applications decide whether to retry, prompt, or close the session.

The library must not silently downgrade a requested security mode. If a caller requests a specific mode, failure to negotiate that mode should be visible through the connection status path.
