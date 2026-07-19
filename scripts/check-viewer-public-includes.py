#!/usr/bin/env python3
# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Reject private core headers from application source trees."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP_ROOTS = (
    ROOT / "apps" / "admin",
    ROOT / "apps" / "common",
    ROOT / "apps" / "server",
    ROOT / "apps" / "viewer",
    ROOT / "apps" / "workspace",
    ROOT / "apps" / "x11",
)
INCLUDE_RE = re.compile(r"^\s*#\s*include\s*[<\"]([^>\"]+)[>\"]")


def checked_files() -> list[Path]:
    files: list[Path] = []
    for root in APP_ROOTS:
        if root.exists():
            files.extend(
                path
                for path in root.rglob("*")
                if path.is_file() and path.suffix in {".c", ".h", ".m"}
            )
    return sorted(files)


def main() -> int:
    failures: list[str] = []
    for path in checked_files():
        rel = path.relative_to(ROOT)
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            match = INCLUDE_RE.match(line)
            if not match:
                continue
            include = match.group(1)
            private_header = ROOT / "src" / include
            if (
                include.startswith("../")
                or include.startswith("src/")
                or private_header.is_file()
            ):
                failures.append(f"{rel}:{line_no}: private include {include!r}")
    if failures:
        print("error: apps must include only public librdp headers and app-local headers")
        for failure in failures:
            print(failure)
        return 1
    print("Application public include guardrail passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
