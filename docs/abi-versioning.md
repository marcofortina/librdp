<!--
Copyright (C) 2026 Marco Fortina
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# ABI and Versioning

This document defines compatibility rules for the public C API and binary interface.

## Version model

The project version is declared by CMake. Public documentation and Doxygen comments use the same version family for `@since` tags.

Version changes should follow semantic versioning:

- patch version: bug fixes and documentation changes that do not change public behavior;
- minor version: additive API, new optional features, new protocols, or new backend configuration;
- major version: intentional API or ABI break.

## Public API boundary

The public API is the set of headers under `include/librdp/`. Symbols, types, macros, enum values, structure layouts, callback signatures, and documented ownership rules in these headers form the compatibility surface.

Internal headers under `src/` are not ABI-stable. Applications must not include them.

## Opaque handles

Opaque structs are the default for stateful objects:

- `librdp_settings`;
- `librdp_session`;
- `librdp_surface`;
- future objects that own protocol, transport, or backend state.

Opaque handles allow internal layout changes without breaking ABI. New state should usually be added behind an existing opaque handle rather than exposed through a public struct.

## Public structs

Public structs are value or borrowed-view types. Changing their size, field order, field type, or field meaning is an ABI break unless a struct is explicitly documented as versioned or size-tagged.

Rules for public structs:

- append-only changes are allowed only when all callers pass an explicit size or version field;
- never reuse a reserved field for unrelated meaning without documenting the transition;
- do not expose native OS handles in public structs;
- document pointer ownership and callback lifetime before adding a pointer field.

## Enums and macros

Enum and macro values are part of the ABI when applications can store, compare, or serialize them.

Rules:

- never renumber existing public enum values;
- add new values at the end or in unused ranges;
- keep feature and flag macros stable;
- document whether unknown future values must be ignored or rejected.

## Function compatibility

Changing a public function signature is an ABI break. Changing documented ownership, nullability, threading, or error behavior is an API break even when the C signature is unchanged.

Additive changes should use new functions, new feature flags, or new settings fields behind opaque handles.

## Error codes

`librdp_status` values are public. Existing values must retain their numeric meaning. New error codes should be added only when callers can take a distinct action from the existing codes.

Functions must not start returning a new error code unless the public header documents that code for the function.

## Deprecation

Deprecated API should remain available through at least one minor release after replacement is introduced.

A deprecation should include:

- Doxygen `@warning` or `@note` in the public header;
- replacement API name;
- compatibility behavior;
- release version when the deprecation began.

Removal requires a major version change unless the API was never part of a released public header.

## Symbol visibility

Public symbols use the `librdp_` prefix and are marked with `LIBRDP_API` in public headers. Internal symbols must not be exported intentionally.

The library target builds with hidden symbol visibility by default. Shared builds use the platform export list in `cmake/` so the dynamic symbol table contains only approved public API symbols.

Recommended exported-symbol review:

1. Build the library with the intended packaging flags.
2. List exported symbols with the platform toolchain.
3. Confirm exported public symbols use the `librdp_` prefix.
4. Confirm helper symbols from `src/` are not exported.
5. Compare public headers, generated API docs, and exported symbols before packaging.

## Header policy

Public headers should remain self-contained and usable from C and C++:

- include their own required standard headers;
- keep `extern "C"` guards;
- avoid internal headers;
- avoid platform-specific native types;
- keep comments synchronized with implementation and tests.

## Compatibility checklist

Before merging public API changes:

1. Confirm the change is additive or intentionally major-versioned.
2. Update Doxygen comments with ownership, threading, errors, and `@since`.
3. Add or update unit tests.
4. Update [API](api.md) and caller examples when caller behavior changes.
5. Run CTest and documentation guardrails.
