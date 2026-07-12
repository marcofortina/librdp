#!/usr/bin/env python3
# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Verify repository copyright and SPDX headers."""

from __future__ import annotations

import subprocess
import shutil
import sys
from pathlib import Path

COPYRIGHT = "Copyright (C) 2026 Marco Fortina"
SPDX_PREFIX = "SPDX-License-Identifier:"
SPDX = f"{SPDX_PREFIX} AGPL-3.0-or-later"

EXEMPT_NAMES = {
    "LICENSE",
}

EXEMPT_SUFFIXES = {
    ".gz",
    ".png",
    ".jpg",
    ".jpeg",
    ".webp",
    ".ico",
    ".pdf",
}

EXEMPT_DIRS = {
    ".git",
    "__pycache__",
    "build",
}

EXEMPT_DIR_PREFIXES = (
    "build-",
    "cmake-build-",
)


def tracked_files(repo: Path) -> list[Path]:
    if not (repo / ".git").exists() or not shutil.which("git"):
        return filesystem_files(repo)

    result = subprocess.run(
        ["git", "ls-files"],
        cwd=repo,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        return filesystem_files(repo)
    return [repo / line for line in result.stdout.splitlines() if line]


def filesystem_files(repo: Path) -> list[Path]:
    files: list[Path] = []
    for path in sorted(repo.rglob("*")):
        if path.is_file() and not is_exempt(path, repo):
            files.append(path)
    return files


def is_exempt(path: Path, repo: Path) -> bool:
    rel = path.relative_to(repo)
    if path.name in EXEMPT_NAMES:
        return True
    if path.suffix.lower() in EXEMPT_SUFFIXES:
        return True
    for part in rel.parts:
        if part in EXEMPT_DIRS:
            return True
        if any(part.startswith(prefix) for prefix in EXEMPT_DIR_PREFIXES):
            return True
    return False


def read_prefix(path: Path, limit: int = 4096) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:limit]
    except OSError as exc:
        raise RuntimeError(f"cannot read {path}: {exc}") from exc


def main(argv: list[str]) -> int:
    repo = Path(argv[1]).resolve() if len(argv) > 1 else Path.cwd().resolve()
    missing: list[str] = []
    wrong_license: list[str] = []

    for path in tracked_files(repo):
        if is_exempt(path, repo):
            continue
        prefix = read_prefix(path)
        rel = str(path.relative_to(repo))
        lines = prefix.splitlines()
        spdx_lines = [line.strip() for line in lines if SPDX_PREFIX in line]
        has_copyright = COPYRIGHT in prefix
        has_spdx = any(SPDX in line for line in spdx_lines)
        has_wrong_agpl = any("AGPL-3.0-only" in line for line in spdx_lines)
        if not has_copyright or not has_spdx:
            missing.append(rel)
        if has_wrong_agpl:
            wrong_license.append(rel)

    if missing:
        print("Files missing required copyright/SPDX header:", file=sys.stderr)
        for rel in missing:
            print(f"  {rel}", file=sys.stderr)
    if wrong_license:
        print("Files using AGPL-3.0-only instead of AGPL-3.0-or-later:", file=sys.stderr)
        for rel in wrong_license:
            print(f"  {rel}", file=sys.stderr)

    return 1 if missing or wrong_license else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
