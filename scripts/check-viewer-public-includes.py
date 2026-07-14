#!/usr/bin/env python3
# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Reject private core headers from the X11 viewer source tree."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VIEWER_ROOT = ROOT / "apps" / "x11-viewer"
PRIVATE_PREFIXES = (
    "channels/",
    "client/",
    "common/",
    "graphics/",
    "licensing/",
    "nla/",
    "platform/",
    "protocol/",
    "security/",
    "transport/",
    "x224/",
)
INCLUDE_RE = re.compile(r"^\s*#\s*include\s*[<\"]([^>\"]+)[>\"]")


def checked_files() -> list[Path]:
    return sorted(
        path
        for path in VIEWER_ROOT.rglob("*")
        if path.is_file() and path.suffix in {".c", ".h"}
    )


def main() -> int:
    failures: list[str] = []
    for path in checked_files():
        rel = path.relative_to(ROOT)
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            match = INCLUDE_RE.match(line)
            if not match:
                continue
            include = match.group(1)
            if include.startswith("../") or include.startswith("src/") or include.startswith(PRIVATE_PREFIXES):
                failures.append(f"{rel}:{line_no}: private include {include!r}")
    if failures:
        print("error: X11 viewer must include only public librdp headers and viewer-local headers")
        for failure in failures:
            print(failure)
        return 1
    print("X11 viewer public include guardrail passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
