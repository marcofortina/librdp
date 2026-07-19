<!--
Copyright (C) 2026 Marco Fortina
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Administration Tools

librdp provides a small administration API for tools that need RDS session
inventory and bounded user actions. The API lives in `<librdp/admin.h>` and is
kept separate from the viewer session API: administration transports, action
authorization, and operator UI are explicit application concerns.

The `librdp-admin` application uses the same public API on every supported
platform. X11 builds present an X11 summary window and macOS builds present an
AppKit summary window. `--no-window` keeps the tool suitable for terminals and
automation.

## Query Sessions

```sh
librdp-admin \
  --endpoint https://rds.example.com:5986/wsman \
  --user operator \
  --password-env RDS_ADMIN_PASSWORD \
  --no-window
```

The endpoint, credentials, domain, timeout, and TLS policy are copied into a
`librdp_admin_config`. Session entries returned by the API are borrowed from the
admin handle and remain valid until the next query, clear, or free operation.

## Execute Actions

Actions are deliberately narrow. The public action object identifies one target
session and one explicit operation:

- disconnect;
- logoff;
- message.

The tools require `--confirm` before sending actions that affect a remote user.
Message text is copied into the action object before execution. Passwords are
read from the configured source and are not printed.

```sh
librdp-admin \
  --endpoint https://rds.example.com:5986/wsman \
  --user operator \
  --password-env RDS_ADMIN_PASSWORD \
  --action message \
  --session-id 4 \
  --message-text "Maintenance starts at 18:00" \
  --confirm \
  --no-window
```

## Native Windows

The same endpoint, credential, and action options apply to both native
frontends:

```sh
librdp-admin \
  --endpoint https://rds.example.com:5986/wsman \
  --user operator \
  --password-env RDS_ADMIN_PASSWORD
```

## Integration Notes

Applications should keep administration credentials separate from viewer
credentials. Trace output reports endpoint and action metadata, but it must not
log passwords, raw authorization headers, or user message contents.

See also: [API reference](api-reference.md), [Programmer's reference](programmers-reference.md),
and [librdp-admin(1)](man/librdp-admin.1).
