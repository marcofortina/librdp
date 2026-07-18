#!/usr/bin/env python3
# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Require module contract comments in internal and viewer headers."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHECKED_ROOTS = (
    Path("apps/common"),
    Path("src"),
    Path("apps/x11/viewer"),
)
REQUIRED_FIELDS = (
    "Module:",
    "Invariants:",
    "Ownership:",
    "Threading:",
    "Trust boundary:",
)


def checked_files() -> list[Path]:
    files: list[Path] = []
    for path in sorted(ROOT.rglob("*.h")):
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT)
        if any(rel == root or rel.is_relative_to(root) for root in CHECKED_ROOTS):
            files.append(path)
    return files


def has_contract_comment(path: Path) -> bool:
    head = "\n".join(path.read_text(encoding="utf-8").splitlines()[:45])
    return all(field in head for field in REQUIRED_FIELDS)


def main() -> int:
    missing = [path for path in checked_files() if not has_contract_comment(path)]
    if missing:
        print("error: internal header comment guardrail failed:", file=sys.stderr)
        for path in missing:
            print(f"  {path.relative_to(ROOT)}", file=sys.stderr)
        return 1
    print(f"Internal header comment guardrail passed ({len(checked_files())} files).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
