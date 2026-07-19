#!/usr/bin/env python3
# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Report unusually large source files without failing the build."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOTS = ("src", "apps", "examples", "tests", "fuzz")
SOURCE_SUFFIXES = {".c", ".m"}
LINE_LIMIT = 3000
BASELINE_LIMITS = {
    "src/channels/composited_remoting.c": 3375,
    "src/channels/graphics_pipeline.c": 3127,
    "src/client/session.c": 6152,
    "src/client/session_filesystem.c": 4614,
    "src/client/session_gdi.c": 4496,
    "src/client/session_graphics_pipeline.c": 3055,
    "src/client/session_smartcard.c": 3007,
    "src/graphics/gdi_backend.c": 5461,
    "tests/test_core_support.c": 3399,
    "tests/test_protocol_channels.c": 5350,
    "tests/test_protocol_graphics.c": 5035,
    "tests/test_server_runtime.c": 3528,
}


def source_files() -> list[Path]:
    files: list[Path] = []

    for root_name in SOURCE_ROOTS:
        root = ROOT / root_name
        if not root.is_dir():
            raise FileNotFoundError(root)
        files.extend(path for path in root.rglob("*") if path.is_file() and path.suffix in SOURCE_SUFFIXES)
    return sorted(files)


def line_count(path: Path) -> int:
    return len(path.read_text(encoding="utf-8", errors="replace").splitlines())


def main() -> int:
    files = source_files()
    observed = {path.relative_to(ROOT).as_posix(): line_count(path) for path in files}
    warnings: list[str] = []

    for relative, count in observed.items():
        baseline = BASELINE_LIMITS.get(relative)
        if count <= LINE_LIMIT:
            continue
        if baseline is None:
            warnings.append(f"{relative}: new large source has {count} lines")
        elif count > baseline:
            warnings.append(f"{relative}: grew from baseline {baseline} to {count} lines")

    for relative in sorted(BASELINE_LIMITS):
        if relative not in observed:
            warnings.append(f"{relative}: stale size baseline for missing source")
        elif observed[relative] <= LINE_LIMIT:
            warnings.append(f"{relative}: size baseline can be removed")

    for warning in warnings:
        print(f"warning: source size advisory: {warning}")
    print(
        f"Source size advisory checked {len(files)} files "
        f"({len(BASELINE_LIMITS)} baselines, {len(warnings)} warnings)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
