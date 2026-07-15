<!--
Copyright (C) 2026 Marco Fortina
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Workspace Feeds

The workspace API loads RDS feed documents and exposes published desktops or
RemoteApp entries through `<librdp/workspace.h>`. A workspace handle owns the
feed configuration and the parsed resource list; resource views returned to the
application are borrowed.

The command-line frontends are:

- `librdp-x11-workspace`;
- `librdp-cocoa-workspace`.

Both can list resources, select one resource, and launch a viewer process with
the target and resource metadata supplied by the feed.

## List Resources

```sh
librdp-x11-workspace \
  --feed https://rds.example.com/RDWeb/Feed/webfeed.aspx \
  --user user \
  --password-env RDS_PASSWORD
```

The tool prints each resource with its index, type, display name, target, and
RemoteApp alias when present. The GUI window mirrors the same list for manual
selection.

## Select And Launch

The launch flow is:

1. fetch the feed;
2. parse published resources;
3. choose a resource by index;
4. construct viewer arguments from the resource type and target;
5. start the configured viewer executable.

```sh
librdp-x11-workspace \
  --feed https://rds.example.com/RDWeb/Feed/webfeed.aspx \
  --user user \
  --password-env RDS_PASSWORD \
  --select 0 \
  --launch \
  --viewer build/librdp-x11-viewer
```

For RemoteApp resources the workspace launcher passes the RemoteApp program
through the viewer `--rail app=...` option. For desktop resources it starts a
normal viewer connection.

## Cocoa

The Cocoa workspace frontend accepts the same feed, credential, selection, and
viewer options:

```sh
librdp-cocoa-workspace \
  --feed https://rds.example.com/RDWeb/Feed/webfeed.aspx \
  --select 0 \
  --launch \
  --viewer build-macos/librdp-cocoa-viewer
```

## Integration Notes

Applications that embed the workspace API should copy any resource fields they
need after the next fetch or clear operation. Feed credentials are sensitive and
must not be logged. Launchers should avoid passing passwords on command lines
when a safer local credential source is available.

See also: [API reference](api-reference.md), [librdp-workspace(7)](man/librdp-workspace.7),
[librdp-x11-workspace(1)](man/librdp-x11-workspace.1), and
[librdp-cocoa-workspace(1)](man/librdp-cocoa-workspace.1).
