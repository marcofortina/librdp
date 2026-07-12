#!/usr/bin/env python3
# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Validate required Markdown documentation and local links."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REQUIRED = (
    "README.md",
    "docs/build.md",
    "docs/api.md",
    "docs/architecture.md",
    "docs/protocol-support.md",
    "docs/security.md",
    "docs/tracing.md",
    "docs/testing.md",
    "docs/fuzzing.md",
    "docs/backends.md",
    "docs/viewer-x11.md",
)
LINK_RE = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")


def has_required_header(path: Path) -> bool:
    prefix = path.read_text(encoding="utf-8")[:512]
    return "Copyright (C) 2026 Marco Fortina" in prefix and "SPDX-License-Identifier: AGPL-3.0-or-later" in prefix


def link_target_exists(path: Path, target: str) -> bool:
    if "://" in target or target.startswith("mailto:"):
        return True
    clean = target.split("#", 1)[0]
    if not clean:
        return True
    return (path.parent / clean).resolve().exists()


def main() -> int:
    errors: list[str] = []
    for rel in REQUIRED:
        path = ROOT / rel
        if not path.is_file():
            errors.append(f"missing required document: {rel}")
            continue
        if not has_required_header(path):
            errors.append(f"missing document header: {rel}")
        text = path.read_text(encoding="utf-8")
        for match in LINK_RE.finditer(text):
            target = match.group(1).strip()
            if not link_target_exists(path, target):
                errors.append(f"broken link in {rel}: {target}")

    if errors:
        print("error: documentation guardrail failed:", file=sys.stderr)
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        return 1
    print(f"Documentation guardrail passed ({len(REQUIRED)} files).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
