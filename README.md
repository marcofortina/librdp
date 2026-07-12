<!--
Copyright (C) 2026 Marco Fortina
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# librdp

librdp is a C client library for building RDP viewers and integration tools on Unix-like systems. The core is platform-neutral and exposes session, settings, event, surface, input, audio, video, clipboard, and channel APIs.

The project targets Linux, macOS, and FreeBSD. Platform-specific behavior is kept behind viewer or backend boundaries.

Protocol coverage, backend availability, validation status, and operational details are tracked in the documentation below.

## Documentation

- [Build](docs/build.md)
- [API](docs/api.md)
- [Architecture](docs/architecture.md)
- [Protocol support](docs/protocol-support.md)
- [Security](docs/security.md)
- [Tracing](docs/tracing.md)
- [Testing](docs/testing.md)
- [Fuzzing](docs/fuzzing.md)
- [Backends](docs/backends.md)
- [X11 viewer](docs/viewer-x11.md)
