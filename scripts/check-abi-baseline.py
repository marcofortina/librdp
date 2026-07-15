#!/usr/bin/env python3
# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Validate exported public symbols and public C type layouts against a baseline."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional


def run_command(args: list[str], *, required: bool = True) -> Optional[str]:
    result = subprocess.run(args, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        if not required:
            return None
        raise RuntimeError(f"{' '.join(args)} failed with {result.returncode}: {result.stderr.strip()}")
    return result.stdout


def parse_symbol_output(output: str) -> set[str]:
    symbols: set[str] = set()
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or " UND " in line or stripped.startswith("Num:"):
            continue
        if re.match(r"^\d+:", stripped) and not re.search(r"\b(GLOBAL|WEAK)\b", stripped):
            continue
        if not re.match(r"^(\d+:|[0-9A-Fa-f]+[ \t]+[A-Za-z][ \t]+|[_A-Za-z][_A-Za-z0-9]*[ \t]+[A-Za-z][ \t])", stripped):
            continue
        match = re.search(r"(^|[ \t])(_?librdp_[A-Za-z0-9_]+(?:@@?[^ \t]+)?)($|[ \t])", stripped)
        if not match:
            continue
        symbol = re.sub(r"@@?.*$", "", match.group(2))
        if symbol.startswith("_librdp_"):
            symbol = symbol[1:]
        symbols.add(symbol)
    return symbols


def exported_symbols(library: Path) -> set[str]:
    readelf = shutil.which("readelf")
    nm = shutil.which("nm")
    attempts: list[list[str]] = []
    if sys.platform == "darwin":
        if nm:
            attempts.append([nm, "-gU", str(library)])
            attempts.append([nm, "-g", str(library)])
        else:
            raise RuntimeError("nm is required for Mach-O ABI symbol validation")
    else:
        if readelf:
            attempts.append([readelf, "--dyn-syms", "--wide", str(library)])
            attempts.append([readelf, "-Ws", str(library)])
            attempts.append([readelf, "-s", str(library)])
        if nm:
            attempts.append([nm, "-D", "--defined-only", str(library)])
            attempts.append([nm, "-gP", str(library)])
            attempts.append([nm, "-g", str(library)])
    if not attempts:
        raise RuntimeError("readelf or nm is required for ABI symbol validation")
    for attempt in attempts:
        output = run_command(attempt, required=False)
        if output is None:
            continue
        symbols = parse_symbol_output(output)
        if symbols:
            return symbols
    raise RuntimeError("unable to inspect exported ABI symbols with readelf or nm")


def abi_key(probe: dict[str, object]) -> str:
    abi = probe.get("abi", {})
    if not isinstance(abi, dict):
        raise RuntimeError("probe output does not contain an abi object")
    return f"ptr{abi.get('pointer_size')}_long{abi.get('long_size')}_size_t{abi.get('size_t_size')}"


def type_map(types: object) -> dict[str, tuple[int, int]]:
    if not isinstance(types, list):
        raise RuntimeError("type layout list is missing")
    result: dict[str, tuple[int, int]] = {}
    for entry in types:
        if not isinstance(entry, dict):
            raise RuntimeError("type layout entry is not an object")
        name = entry.get("name")
        size = entry.get("size")
        align = entry.get("align")
        if not isinstance(name, str) or not isinstance(size, int) or not isinstance(align, int):
            raise RuntimeError("type layout entry has invalid fields")
        result[name] = (size, align)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--library", required=True, type=Path)
    parser.add_argument("--probe", required=True, type=Path)
    args = parser.parse_args()

    baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
    probe = json.loads(run_command([str(args.probe)]))

    current_symbols = exported_symbols(args.library)
    expected_symbols = set(baseline.get("symbols", []))
    missing_symbols = sorted(expected_symbols - current_symbols)

    layouts = baseline.get("layouts", {})
    if not isinstance(layouts, dict):
        raise RuntimeError("baseline layouts object is missing")
    key = abi_key(probe)
    expected_layouts = layouts.get(key)
    missing_types: list[str] = []
    changed_types: list[str] = []
    if expected_layouts is not None:
        current_types = type_map(probe.get("types"))
        for name, expected in type_map(expected_layouts).items():
            current = current_types.get(name)
            if current is None:
                missing_types.append(name)
            elif current != expected:
                changed_types.append(
                    f"{name}: expected size={expected[0]} align={expected[1]}, "
                    f"got size={current[0]} align={current[1]}"
                )

    if missing_symbols or missing_types or changed_types:
        print("error: ABI baseline validation failed", file=sys.stderr)
        if missing_symbols:
            print("missing exported symbols:", file=sys.stderr)
            for symbol in missing_symbols:
                print(f"  {symbol}", file=sys.stderr)
        if missing_types:
            print("missing public type layouts:", file=sys.stderr)
            for name in missing_types:
                print(f"  {name}", file=sys.stderr)
        if changed_types:
            print("changed public type layouts:", file=sys.stderr)
            for item in changed_types:
                print(f"  {item}", file=sys.stderr)
        return 1

    if expected_layouts is None:
        print(f"ABI symbol baseline passed; no type layout baseline for {key}")
    else:
        print(f"ABI baseline passed for {key}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
