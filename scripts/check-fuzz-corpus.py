#!/usr/bin/env python3
# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Validate fuzz corpus coverage and reject accidental seed duplication."""

from __future__ import annotations

import hashlib
import re
import sys
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FUZZ_CMAKE = ROOT / "cmake" / "Fuzz.cmake"
CORPUS_ROOT = ROOT / "fuzz" / "corpus"
TARGET_PATTERN = re.compile(r"add_librdp_fuzzer\((fuzz_[a-z0-9_]+)\s+")
REQUIRED_SEEDS = ("empty.bin", "structured.bin", "truncated.bin")
ALLOWED_DUPLICATE_GROUPS: frozenset[frozenset[str]] = frozenset()


def configured_targets() -> list[str]:
    text = FUZZ_CMAKE.read_text(encoding="utf-8")
    return sorted(set(TARGET_PATTERN.findall(text)))


def duplicate_key(paths: list[Path]) -> frozenset[str]:
    return frozenset(path.relative_to(CORPUS_ROOT).as_posix() for path in paths)


def main() -> int:
    errors: list[str] = []
    targets = configured_targets()
    target_set = set(targets)
    directories = {path.name for path in CORPUS_ROOT.iterdir() if path.is_dir()}
    hashes: dict[str, list[Path]] = defaultdict(list)

    for target in targets:
        corpus = CORPUS_ROOT / target
        if not corpus.is_dir():
            errors.append(f"{target}: missing corpus directory")
            continue
        for name in REQUIRED_SEEDS:
            seed = corpus / name
            if not seed.is_file():
                errors.append(f"{target}: missing {name}")
                continue
            payload = seed.read_bytes()
            if name != "empty.bin" and not payload:
                errors.append(f"{target}: {name} must not be empty")
        structured = corpus / "structured.bin"
        truncated = corpus / "truncated.bin"
        if structured.is_file() and b"fuzz_" in structured.read_bytes():
            errors.append(f"{target}: structured.bin contains a generic target marker")
        if structured.is_file() and truncated.is_file():
            full = structured.read_bytes()
            prefix = truncated.read_bytes()
            if prefix and (len(prefix) >= len(full) or not full.startswith(prefix)):
                errors.append(f"{target}: truncated.bin is not a strict structured.bin prefix")
        for seed in sorted(corpus.glob("*.bin")):
            payload = seed.read_bytes()
            if payload:
                hashes[hashlib.sha256(payload).hexdigest()].append(seed)

    for extra in sorted(directories - target_set):
        errors.append(f"{extra}: corpus directory has no configured fuzz target")

    for digest, paths in sorted(hashes.items()):
        if len(paths) < 2:
            continue
        key = duplicate_key(paths)
        if key not in ALLOWED_DUPLICATE_GROUPS:
            joined = ", ".join(sorted(key))
            errors.append(f"duplicate seed {digest[:12]}: {joined}")

    if errors:
        print("error: fuzz corpus validation failed:", file=sys.stderr)
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        return 1
    seed_count = sum(1 for path in CORPUS_ROOT.glob("*/*.bin"))
    print(f"Fuzz corpus validation passed ({len(targets)} targets, {seed_count} seeds).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
