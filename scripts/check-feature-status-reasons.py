#!/usr/bin/env python3
# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
OLD_ENUM = "LIBRDP_FEATURE_REASON_" + "PARSER" + "_ONLY"
OLD_PHRASES = (
    "parser" + "-only",
    "parser" + " only",
    "parser" + "_only",
    "PARSER" + "_ONLY",
)
IGNORED_DIRS = {
    ".git",
    "__pycache__",
}
IGNORED_PREFIXES = (
    "build",
    "cmake-build",
    "Testing",
)


def tracked_files():
    try:
        output = subprocess.check_output(
            ["git", "-C", str(ROOT), "ls-files", "-z"],
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError):
        output = b""

    if output:
        for item in output.split(b"\0"):
            if item:
                yield ROOT / item.decode("utf-8", errors="strict")
        return

    for path in sorted(ROOT.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT)
        parts = set(relative.parts)
        if parts & IGNORED_DIRS:
            continue
        if any(str(relative).startswith(prefix) for prefix in IGNORED_PREFIXES):
            continue
        yield path


def read_text(path):
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return None


def main():
    errors = []
    for path in tracked_files():
        text = read_text(path)
        if text is None:
            continue
        relative = path.relative_to(ROOT)
        if OLD_ENUM in text:
            errors.append(f"{relative}: contains removed feature-status reason enum")
            continue
        lowered = text.lower()
        for phrase in OLD_PHRASES:
            if phrase.lower() in lowered:
                errors.append(f"{relative}: mentions removed feature-status reason category")
                break

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
