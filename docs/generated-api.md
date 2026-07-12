<!--
Copyright (C) 2026 Marco Fortina
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Generated API Documentation

The generated API documentation is built from the Doxygen comments in the public headers under `include/librdp/`.

It contains per-symbol pages for:

- public functions;
- public structs;
- public enums and enum values;
- public macros;
- callback types;
- grouped API families;
- parameter documentation;
- return-code documentation;
- ownership and lifetime notes;
- threading notes;
- security warnings;
- version tags.

## Published reference

[Open the generated Doxygen API reference](https://marcofortina.github.io/librdp/api/doxygen/html/index.html)

Generated API groups:

| API family | Generated group |
| --- | --- |
| Umbrella header | [Umbrella Header](https://marcofortina.github.io/librdp/api/doxygen/html/group__librdp__umbrella.html) |
| Errors | [Error API](https://marcofortina.github.io/librdp/api/doxygen/html/group__librdp__error.html) |
| Settings | [Settings API](https://marcofortina.github.io/librdp/api/doxygen/html/group__librdp__settings.html) |
| Session | [Session API](https://marcofortina.github.io/librdp/api/doxygen/html/group__librdp__session.html) |
| Events | [Event API](https://marcofortina.github.io/librdp/api/doxygen/html/group__librdp__event.html) |
| Surface | [Surface API](https://marcofortina.github.io/librdp/api/doxygen/html/group__librdp__surface.html) |
| Input | [Input API](https://marcofortina.github.io/librdp/api/doxygen/html/group__librdp__input.html) |
| Clipboard | [Clipboard API](https://marcofortina.github.io/librdp/api/doxygen/html/group__librdp__clipboard.html) |
| Dynamic channels | [Dynamic Channel API](https://marcofortina.github.io/librdp/api/doxygen/html/group__librdp__channel.html) |
| Audio | [Audio API](https://marcofortina.github.io/librdp/api/doxygen/html/group__librdp__audio.html) |
| Video | [Video API](https://marcofortina.github.io/librdp/api/doxygen/html/group__librdp__video.html) |

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

## Source of truth

The source of truth for individual API documentation is the Doxygen block immediately above each declaration in `include/librdp/*.h`.

Do not duplicate full function documentation by hand in Markdown. Update the public header comment, regenerate the Doxygen reference, and keep the Markdown pages focused on navigation, concepts, examples, and integration guidance.
