<!--
Copyright (C) 2026 Marco Fortina
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Generated API Documentation

The Doxygen output is built from public headers under `include/librdp/` and
contains the per-symbol reference for functions, types, macros, callbacks,
parameters, return codes, ownership, threading, security notes, and `@since`
tags.

## Published reference

[Open the generated Doxygen API reference](https://marcofortina.github.io/librdp/api/doxygen/html/index.html)

Group pages: [umbrella](https://marcofortina.github.io/librdp/api/doxygen/html/group__librdp__umbrella.html),
[admin](https://marcofortina.github.io/librdp/api/doxygen/html/group__librdp__admin.html),
[client](https://marcofortina.github.io/librdp/api/doxygen/html/group__librdp__client.html),
[error](https://marcofortina.github.io/librdp/api/doxygen/html/group__librdp__error.html),
[settings](https://marcofortina.github.io/librdp/api/doxygen/html/group__librdp__settings.html),
[session](https://marcofortina.github.io/librdp/api/doxygen/html/group__librdp__session.html),
[event](https://marcofortina.github.io/librdp/api/doxygen/html/group__librdp__event.html),
[surface](https://marcofortina.github.io/librdp/api/doxygen/html/group__librdp__surface.html),
[input](https://marcofortina.github.io/librdp/api/doxygen/html/group__librdp__input.html),
[clipboard](https://marcofortina.github.io/librdp/api/doxygen/html/group__librdp__clipboard.html),
[channel](https://marcofortina.github.io/librdp/api/doxygen/html/group__librdp__channel.html),
[audio](https://marcofortina.github.io/librdp/api/doxygen/html/group__librdp__audio.html), and
[video](https://marcofortina.github.io/librdp/api/doxygen/html/group__librdp__video.html), and
[workspace](https://marcofortina.github.io/librdp/api/doxygen/html/group__librdp__workspace.html).

The GitHub Pages workflow builds this reference with Doxygen and publishes it under:

```text
api/doxygen/html/
```

## Local build

Generate the same HTML reference locally with:

```sh
cmake -S . -B build -DLIBRDP_BUILD_TESTS=ON
cmake --build build --target docs-api
```

Then open:

```text
build/doxygen/html/index.html
```

Update the public header comments before regenerating this reference.
