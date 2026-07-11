#!/usr/bin/env python3
# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Require explanatory comments before large security/protocol hotspots."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHECKED_DIRS = ("src",)
CHECKED_SUFFIXES = {".c"}
MIN_HOTSPOT_LINES = 180
CRITICAL_NAME_PARTS = (
    "auth",
    "channel",
    "clipboard",
    "credssp",
    "decode",
    "device",
    "dispatch",
    "graphics",
    "handle",
    "input",
    "parse",
    "process",
    "security",
    "send",
    "usb",
    "video",
    "webauthn",
)
CONTROL_KEYWORDS = {"if", "for", "while", "switch", "return", "sizeof"}


@dataclass(frozen=True)
class FunctionDefinition:
    path: Path
    line: int
    end_line: int
    name: str
    has_comment: bool

    @property
    def body_lines(self) -> int:
        return self.end_line - self.line + 1


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


def is_identifier(value: str) -> bool:
    return bool(value) and (value[0].isalpha() or value[0] == "_") and all(
        char.isalnum() or char == "_" for char in value
    )


def find_statement_start(text: str, open_brace: int) -> int:
    cursor = open_brace - 1
    while cursor >= 0:
        if text[cursor] in ";}":
            return cursor + 1
        cursor -= 1
    return 0


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


def candidate_name(statement: str) -> str | None:
    compact = " ".join(statement.strip().split())
    if not compact or compact.startswith("#") or compact.startswith("typedef "):
        return None
    close_paren = compact.rfind(")")
    open_paren = compact.rfind("(", 0, close_paren)
    if open_paren <= 0:
        return None
    cursor = open_paren - 1
    while cursor >= 0 and compact[cursor].isspace():
        cursor -= 1
    end = cursor + 1
    while cursor >= 0 and (compact[cursor].isalnum() or compact[cursor] == "_"):
        cursor -= 1
    name = compact[cursor + 1 : end]
    if not is_identifier(name) or name in CONTROL_KEYWORDS:
        return None
    return name


def signature_start_offset(statement: str, name: str) -> int:
    name_offset = statement.rfind(name)
    if name_offset < 0:
        return 0
    line_start = statement.rfind("\n", 0, name_offset) + 1
    while line_start > 0:
        previous_line_start = statement.rfind("\n", 0, line_start - 1) + 1
        previous_line = statement[previous_line_start : line_start - 1].strip()
        if not previous_line or previous_line.startswith("#") or previous_line in {"}", "};"}:
            break
        line_start = previous_line_start
    return line_start


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


def collect_definitions(path: Path) -> list[FunctionDefinition]:
    original = path.read_text(encoding="utf-8")
    sanitized = strip_comments_and_strings(original)
    lines = original.splitlines()
    definitions: list[FunctionDefinition] = []
    depth = 0
    index = 0
    while index < len(sanitized):
        char = sanitized[index]
        if char == "{":
            if depth == 0:
                start = find_statement_start(sanitized, index)
                statement = sanitized[start:index]
                name = candidate_name(statement)
                if name is not None:
                    end = find_matching_brace(sanitized, index)
                    signature_start = start + signature_start_offset(statement, name)
                    start_line = sanitized.count("\n", 0, signature_start) + 1
                    end_line = sanitized.count("\n", 0, end) + 1
                    definitions.append(
                        FunctionDefinition(path, start_line, end_line, name, has_nearby_comment(lines, start_line - 1))
                    )
            depth += 1
        elif char == "}":
            depth = max(0, depth - 1)
        index += 1
    return definitions


def checked_files() -> list[Path]:
    files: list[Path] = []
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT)
        if rel.parts and rel.parts[0] in CHECKED_DIRS and rel.suffix in CHECKED_SUFFIXES:
            files.append(path)
    return files


def is_hotspot(definition: FunctionDefinition) -> bool:
    if definition.body_lines < MIN_HOTSPOT_LINES:
        return False
    lower = definition.name.lower()
    return any(part in lower for part in CRITICAL_NAME_PARTS)


def main() -> int:
    hotspots: list[FunctionDefinition] = []
    for path in checked_files():
        hotspots.extend(definition for definition in collect_definitions(path) if is_hotspot(definition))
    findings = [definition for definition in hotspots if not definition.has_comment]

    if findings:
        print("error: source hotspot comment guardrail failed:", file=sys.stderr)
        for finding in findings:
            rel = finding.path.relative_to(ROOT)
            print(f"  {rel}:{finding.line}: {finding.name} ({finding.body_lines} lines)", file=sys.stderr)
        return 1
    print(f"Source hotspot comment guardrail passed ({len(hotspots)} hotspots).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
