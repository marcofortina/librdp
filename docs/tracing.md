<!--
Copyright (C) 2026 Marco Fortina
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Tracing

Runtime trace is disabled by default and writes to `stderr`. It is intended for interoperability and performance debugging without requiring external logging dependencies.

## Environment variables

- `LIBRDP_TRACE_CLIENT=1`: enable client lifecycle, viewer, graphics, input, surface, clipboard, channel, audio, video, and device events.
- `LIBRDP_TRACE_TRANSPORT=1`: enable TCP, TLS, UDP, read, write, wait, timeout, EOF, and wakeup events.
- `LIBRDP_TRACE_PROTOCOL=1`: enable handshake, parser, PDU, security, capability, channel, fast-path, slow-path, and codec protocol events.
- `LIBRDP_TRACE_HEX_BYTES=<bytes>`: maximum bytes emitted by protocol hexdumps.
- `LIBRDP_TRACE_LEVEL=<level>`: filter event verbosity.

Accepted boolean values are `1`, `true`, `TRUE`, `yes`, `YES`, `on`, and `ON`.

Trace levels are:

- `error` or `0`;
- `warn` or `1`;
- `info` or `2`;
- `debug` or `3`;
- `trace` or `4`.

Invalid `LIBRDP_TRACE_HEX_BYTES` values fall back to zero. Hexdumps are never unlimited. Protocol hexdumps require `LIBRDP_TRACE_PROTOCOL=1`, `LIBRDP_TRACE_LEVEL=trace`, and a non-zero hex byte limit.

## Event format

Normal events use stable key-value fields:

```text
librdp trace seq=<n> ts_ns=<n> elapsed_us=<n> category=<client|transport|protocol> event=<name> level=<level> message="<fields>"
```

Protocol hexdumps use:

```text
librdp trace seq=<n> ts_ns=<n> elapsed_us=<n> category=protocol event=<name> level=trace payload_len=<n> dumped=<n> hex=<bytes> ascii="<ascii>"
```

`seq` is monotonic within the process. `elapsed_us` measures time since the first emitted trace line.

## Common commands

Client and protocol trace without hexdumps:

```sh
LIBRDP_TRACE_CLIENT=1 LIBRDP_TRACE_PROTOCOL=1 build/librdp-x11-viewer --target host --security nla
```

Full protocol hexdumps capped at 96 bytes:

```sh
LIBRDP_TRACE_CLIENT=1 LIBRDP_TRACE_TRANSPORT=1 LIBRDP_TRACE_PROTOCOL=1 LIBRDP_TRACE_LEVEL=trace LIBRDP_TRACE_HEX_BYTES=96 build/librdp-x11-viewer --target host --security nla
```

Transport timing only:

```sh
LIBRDP_TRACE_TRANSPORT=1 LIBRDP_TRACE_LEVEL=debug build/librdp-x11-viewer --target host
```

## Operational rules

Trace event names are lower-case and hierarchical. New trace events should be stable once shipped because automated analysis can filter on them.

Trace must not print credentials or unbounded payloads. Sensitive fields should be omitted rather than redacted when the value is not needed for debugging.
