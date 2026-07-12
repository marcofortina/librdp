#!/usr/bin/env python3
# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Require focused documentation for complex tests and fuzz targets."""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEST_DIR = ROOT / "tests"
FUZZ_DIR = ROOT / "fuzz"
MODULE_FIELDS = (
    "Module:",
    "Coverage:",
    "Bug classes:",
    "Determinism:",
)
FUZZ_ENTRY_FIELDS = (
    "Fuzz target:",
    "Bug classes:",
)
MIN_COMPLEX_TEST_LINES = 100
TEST_FUNCTION_PREFIXES = (
    "test_",
    "build_",
    "make_",
    "run_",
    "start_",
)


@dataclass(frozen=True)
class Function:
    path: Path
    name: str
    line: int
    end_line: int
    has_comment: bool

    @property
    def body_lines(self) -> int:
        return self.end_line - self.line + 1


def checked_files() -> list[Path]:
    return sorted(TEST_DIR.glob("*.c")) + sorted(FUZZ_DIR.glob("*.c"))


def has_fields(path: Path, fields: tuple[str, ...]) -> bool:
    head = "\n".join(path.read_text(encoding="utf-8").splitlines()[:60])
    return all(field in head for field in fields)


def strip_comments_and_strings(text: str) -> str:
    result: list[str] = []
    index = 0
    state = "normal"
    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""
        if state == "normal":
            if char == "/" and next_char == "*":
                result.extend("  ")
                index += 2
                state = "block_comment"
                continue
            if char == "/" and next_char == "/":
                result.extend("  ")
                index += 2
                state = "line_comment"
                continue
            if char == '"':
                result.append(" ")
                index += 1
                state = "string"
                continue
            if char == "'":
                result.append(" ")
                index += 1
                state = "char"
                continue
            result.append(char)
            index += 1
            continue
        if state == "block_comment":
            if char == "\n":
                result.append("\n")
                index += 1
                continue
            if char == "*" and next_char == "/":
                result.extend("  ")
                index += 2
                state = "normal"
                continue
            result.append(" ")
            index += 1
            continue
        if state == "line_comment":
            if char == "\n":
                result.append("\n")
                index += 1
                state = "normal"
                continue
            result.append(" ")
            index += 1
            continue
        if state in {"string", "char"}:
            if char == "\n":
                result.append("\n")
                index += 1
                state = "normal"
                continue
            if char == "\\" and next_char:
                result.extend("  ")
                index += 2
                continue
            if (state == "string" and char == '"') or (state == "char" and char == "'"):
                result.append(" ")
                index += 1
                state = "normal"
                continue
            result.append(" ")
            index += 1
            continue
    return "".join(result)


def previous_significant_line(lines: list[str], index: int) -> str:
    cursor = index - 1
    while cursor >= 0:
        line = lines[cursor].strip()
        if line:
            return line
        cursor -= 1
    return ""


def has_nearby_comment(lines: list[str], index: int) -> bool:
    line = previous_significant_line(lines, index)
    return line.endswith("*/") or line.startswith("/*") or line.startswith("//")


def find_matching_brace(text: str, open_brace: int) -> int:
    depth = 0
    for cursor in range(open_brace, len(text)):
        if text[cursor] == "{":
            depth += 1
        elif text[cursor] == "}":
            depth -= 1
            if depth == 0:
                return cursor
    return open_brace


def collect_functions(path: Path) -> list[Function]:
    original = path.read_text(encoding="utf-8")
    sanitized = strip_comments_and_strings(original)
    lines = original.splitlines()
    functions: list[Function] = []
    regex = re.compile(
        r"(?m)^(?:static\s+)?(?:int|void|librdp_status|uint\d+_t|size_t|const\s+char\s*\*|librdp_settings\s*\*)\s+"
        r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\("
    )
    for match in regex.finditer(sanitized):
        open_brace = sanitized.find("{", match.end())
        if open_brace < 0:
            continue
        close_brace = find_matching_brace(sanitized, open_brace)
        line = sanitized.count("\n", 0, match.start()) + 1
        end_line = sanitized.count("\n", 0, close_brace) + 1
        functions.append(Function(path, match.group("name"), line, end_line, has_nearby_comment(lines, line - 1)))
    return functions


def fuzz_entry_comment_ok(path: Path) -> bool:
    text = path.read_text(encoding="utf-8")
    offset = text.find("int LLVMFuzzerTestOneInput")
    if offset < 0:
        return False
    prefix = text[:offset].rstrip()
    start = prefix.rfind("/*")
    end = prefix.rfind("*/")
    if start < 0 or end < start:
        return False
    comment = prefix[start : end + 2]
    return all(field in comment for field in FUZZ_ENTRY_FIELDS)


def main() -> int:
    module_missing: list[Path] = []
    fuzz_missing: list[Path] = []
    complex_missing: list[Function] = []
    for path in checked_files():
        if not has_fields(path, MODULE_FIELDS):
            module_missing.append(path)
        if path.parent == FUZZ_DIR and path.name != "fuzz_main.c" and not fuzz_entry_comment_ok(path):
            fuzz_missing.append(path)
        if path.parent == TEST_DIR:
            for function in collect_functions(path):
                if (
                    function.body_lines >= MIN_COMPLEX_TEST_LINES
                    and function.name.startswith(TEST_FUNCTION_PREFIXES)
                    and not function.has_comment
                ):
                    complex_missing.append(function)

    if module_missing or fuzz_missing or complex_missing:
        print("error: test/fuzz comment guardrail failed:", file=sys.stderr)
        if module_missing:
            print("missing module comments:", file=sys.stderr)
            for path in module_missing:
                print(f"  {path.relative_to(ROOT)}", file=sys.stderr)
        if fuzz_missing:
            print("missing fuzz entrypoint comments:", file=sys.stderr)
            for path in fuzz_missing:
                print(f"  {path.relative_to(ROOT)}", file=sys.stderr)
        if complex_missing:
            print("missing complex test/fixture comments:", file=sys.stderr)
            for function in complex_missing:
                print(
                    f"  {function.path.relative_to(ROOT)}:{function.line}: "
                    f"{function.name} ({function.body_lines} lines)",
                    file=sys.stderr,
                )
        return 1
    print(f"Test/fuzz comment guardrail passed ({len(checked_files())} files).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
