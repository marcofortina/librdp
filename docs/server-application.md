<!--
Copyright (C) 2026 Marco Fortina
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Desktop Server Application

`librdp-server` exposes a native desktop through the public server API. CMake
selects an X11 implementation on the supported non-Apple systems and a Cocoa
implementation on macOS. Platform integration remains in the application; the
protocol library has no window-system, authentication-service, or
display-manager dependency.

Build the server with:

```sh
cmake -S . -B build \
  -DLIBRDP_BUILD_SERVER=ON \
  -DLIBRDP_BUILD_TESTS=ON
cmake --build build -j"$(nproc)"
```

## Shadow Sessions

Shadow mode captures a root window, monitor or selected window from the
current graphical session. Capture, input, clipboard and client-drive access
are separate providers and remain disabled until explicitly allowed.

```sh
librdp-server \
  --mode shadow \
  --display :0 \
  --source root \
  --bind 127.0.0.1 \
  --security tls \
  --tls-cert /etc/librdp/server.crt \
  --tls-key /etc/librdp/server.key \
  --allow-capture
```

`--allow-input`, `--allow-clipboard` and `--allow-drive` grant independent
local capabilities. Client drives are read-only unless a writable policy is
selected by the application. The FUSE mount is optional and remains outside
the protocol core.

### macOS Shadow Capture

On macOS, `display:index` selects a ScreenCaptureKit display and `window:id`
selects a CoreGraphics window. Capture requires Screen Recording permission;
remote keyboard and pointer injection require Accessibility permission.

```sh
librdp-server \
  --mode shadow \
  --source display:0 \
  --bind 127.0.0.1 \
  --security tls \
  --tls-cert /etc/librdp/server.crt \
  --tls-key /etc/librdp/server.key \
  --allow-capture
```

`--non-interactive` suppresses native permission requests and consent dialogs.
Required permissions must already be granted. Client-announced drives are
mounted read-only under the isolated `--drive-mount` path when FUSE 3 is
available.

## Managed X11 Sessions

Managed mode separates privileged resource allocation from the desktop
workload:

- `librdp-session-broker` owns policy, display allocation and the local
  control socket;
- `librdp-session-supervisor` performs host authentication and supervises
  one process group;
- `librdp-session-agent` runs with the authenticated account and hosts the
  X11 capture, input, clipboard and drive providers;
- `librdp-server --mode managed` is the unprivileged control client used to
  start, attach, query, resize, detach or terminate a session.

The broker never places credentials in configuration, command arguments,
persistent registry records or diagnostics. The control client reads the
password and reconnect token from named environment variables.

## Broker configuration

The broker accepts an absolute configuration path as its first option:

```sh
librdp-session-broker \
  --config /etc/librdp/session-broker.conf \
  --check-config

librdp-session-broker \
  --config /etc/librdp/session-broker.conf
```

The file uses one `key=value` pair per line. Blank lines and lines beginning
with `#` are ignored. Scalar keys may occur once; `allow-user`, `allow-group`
and `allow-env` may repeat. The file must be a regular file owned by root or
the broker account and must not be writable by its group or other users.
Unknown keys, embedded NUL bytes, oversized files and relative executable or
filesystem paths are rejected.

An example is installed as
`share/librdp/librdp-session-broker.conf.example`.

| Key | Meaning |
| --- | --- |
| `socket`, `runtime-root` | Absolute broker socket and per-session runtime root. |
| `supervisor`, `agent`, `xserver`, `desktop` | Absolute executable paths or, for `desktop`, an absolute command with bounded arguments. |
| `auth-service` | Native host-authentication service name. |
| `bind` | Address used by per-session RDP listeners. |
| `security` | `nla`, `tls` or explicitly enabled `standard`. |
| `tls-cert`, `tls-key` | Absolute certificate and private-key paths for TLS or NLA. |
| `allow-user`, `allow-group` | Optional authenticated-account allowlists. |
| `allow-env` | Environment variable name permitted in the user session. |
| `max-sessions`, `max-sessions-per-user` | Global and per-account session bounds. |
| `first-display`, `last-display` | Managed X display allocation range. |
| `idle-seconds`, `max-duration-seconds` | Session lifetime limits. |
| `socket-mode`, `socket-group` | Local IPC access mode and optional group. |
| `allow-standard-security`, `allow-user-switch` | Security and local identity policy switches. |
| `allow-input`, `allow-clipboard`, `allow-drive` | Provider policy gates. |
| `drive-read-only` | Write policy for client-announced drives. |
| `allow-reconnect`, `persistent` | Detach, reconnect and broker-restart policy. |
| `xvfb` | Deterministic Xvfb provider selection; production configuration normally uses Xorg. |

Boolean values accept `1`, `true`, `yes` or `on`, and their corresponding
false forms, without regard to letter case. Command-line values following the
configuration path override file values.

## Service operation

The broker is a foreground process. A process supervisor should:

1. validate the configuration before replacing a running instance;
2. create the parent runtime directory with root ownership and restrictive
   permissions;
3. start the broker without daemonization;
4. treat creation of the configured Unix socket as readiness;
5. forward `SIGTERM` for orderly shutdown;
6. retain the configured runtime root across broker replacement when
   persistent sessions are enabled.

This contract works with systemd, OpenRC, rc.d and other process supervisors.
No service-manager notification API or display-manager private interface is
required.

## Session control

Start a session with credentials supplied outside the command line:

```sh
export LIBRDP_SERVER_PASSWORD='account password'
librdp-server \
  --mode managed \
  --managed-action start \
  --broker /run/librdp/session-broker.sock \
  --user account \
  --password-env LIBRDP_SERVER_PASSWORD \
  --width 1280 \
  --height 720 \
  --allow-capture \
  --persistent \
  --reconnect
unset LIBRDP_SERVER_PASSWORD
```

The response contains a session identifier, listener address and reconnect
token. Store the token with owner-only permissions and provide it through
`--token-env` for attach, resize, detach or terminate operations.

## Diagnostics

The broker writes stable key/value records to standard error:

```text
librdp x11-session-broker event=config.valid security=nla
librdp x11-session-broker event=broker.start socket="/run/librdp/session-broker.sock" security=nla
librdp x11-session-broker event=broker.stop status=ok
```

Configuration errors report the line, key and reason but never the rejected
value. Protocol and provider details use the normal librdp trace categories.
See [Diagnostics](diagnostics.md) and [Tracing](tracing.md).

## Manual pages

- [librdp-server(1)](man/librdp-server.1)
- [librdp-session-broker(8)](man/librdp-session-broker.8)
- [librdp-server(7)](man/librdp-server.7)
