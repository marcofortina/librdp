#!/usr/bin/env python3
# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Validate documented C examples and their CMake registration."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_RE = re.compile(r"add_librdp_example\((librdp-example-[a-z0-9-]+)\s+(examples/[a-z0-9_]+\.c)\)")


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def has_header(path: Path) -> bool:
    text = path.read_text(encoding="utf-8")[:512]
    return "Copyright (C) 2026 Marco Fortina" in text and "SPDX-License-Identifier: AGPL-3.0-or-later" in text


def cmake_examples() -> dict[str, str]:
    return {match.group(1): match.group(2) for match in EXAMPLE_RE.finditer(read("CMakeLists.txt"))}


def main() -> int:
    errors: list[str] = []
    examples_doc = read("docs/examples.md")
    build_doc = read("docs/build.md")
    cmake = read("CMakeLists.txt")
    examples = cmake_examples()

    if 'option(LIBRDP_BUILD_EXAMPLES "Build example programs" ON)' not in cmake:
        errors.append("CMake missing LIBRDP_BUILD_EXAMPLES option")
    if "LIBRDP_BUILD_EXAMPLES" not in build_doc:
        errors.append("docs/build.md missing LIBRDP_BUILD_EXAMPLES")

    for target, source in sorted(examples.items()):
        path = ROOT / source
        if not path.is_file():
            errors.append(f"example source missing: {source}")
            continue
        if not has_header(path):
            errors.append(f"example source missing license header: {source}")
        if target not in examples_doc:
            errors.append(f"example target missing from docs/examples.md: {target}")
        if source not in examples_doc:
            errors.append(f"example source missing from docs/examples.md: {source}")

    for path in sorted((ROOT / "examples").glob("*.c")):
        rel = str(path.relative_to(ROOT))
        if rel not in examples.values():
            errors.append(f"example source not registered in CMake: {rel}")

    if errors:
        print("error: example guardrail failed:", file=sys.stderr)
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        return 1

    print(f"Example guardrail passed ({len(examples)} examples).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
