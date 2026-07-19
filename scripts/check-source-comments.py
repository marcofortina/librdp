#!/usr/bin/env python3
# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Require explanatory comments for module boundaries and risky C functions."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
CHECKED_ROOTS = (
    Path("src"),
    Path("apps/admin"),
    Path("apps/common"),
    Path("apps/cocoa"),
    Path("apps/viewer"),
    Path("apps/x11/workspace"),
    Path("examples"),
)
CHECKED_SUFFIXES = {".c", ".m"}
MIN_LARGE_FUNCTION_LINES = 120
MIN_RISK_FUNCTION_LINES = 80
MIN_COMPLEX_FUNCTION_LINES = 25
MIN_COMPLEXITY_SCORE = 24
MIN_FUNCTION_COMMENT_WORDS = 18
MODULE_REQUIRED_FIELDS = (
    "Module:",
    "Invariants:",
    "Ownership:",
    "Threading:",
    "Trust boundary:",
)
COMMENT_DETAIL_TERMS = (
    "backend",
    "boundary",
    "bounds",
    "buffer",
    "cache",
    "callback",
    "channel",
    "clip",
    "credential",
    "decode",
    "edge",
    "encode",
    "error",
    "failure",
    "handle",
    "invariant",
    "length",
    "lifetime",
    "ownership",
    "coefficient",
    "cursor",
    "payload",
    "protocol",
    "operation",
    "security",
    "session",
    "state",
    "stream",
    "surface",
    "trace",
    "transport",
    "validate",
    "wire",
)
COMMENT_CONTRACT_TERMS = (
    "apply",
    "boundary",
    "bounds",
    "build",
    "clear",
    "copy",
    "decode",
    "dispatch",
    "emit",
    "encode",
    "error",
    "failure",
    "fallback",
    "flush",
    "handle",
    "invariant",
    "lifetime",
    "map",
    "ownership",
    "parse",
    "policy",
    "present",
    "process",
    "purpose",
    "read",
    "reassemble",
    "render",
    "reject",
    "send",
    "serialize",
    "scope",
    "state",
    "trust",
    "validate",
    "write",
)
CRITICAL_NAME_PARTS = (
    "avc",
    "auth",
    "backend",
    "bitmap",
    "capabil",
    "certificate",
    "channel",
    "clear",
    "clipboard",
    "codec",
    "connect",
    "credssp",
    "decode",
    "device",
    "dispatch",
    "encode",
    "fastpath",
    "gcc",
    "gdi",
    "graphics",
    "handle",
    "input",
    "license",
    "mcs",
    "nla",
    "parse",
    "pointer",
    "process",
    "read",
    "receive",
    "render",
    "rfx",
    "security",
    "send",
    "slowpath",
    "surface",
    "tls",
    "transport",
    "usb",
    "video",
    "webauthn",
    "write",
    "x224",
)
CONTROL_KEYWORDS = {"if", "for", "while", "switch", "return", "sizeof"}
COMMENT_ALLOWLIST: dict[tuple[str, str], str] = {}


@dataclass(frozen=True)
class FunctionDefinition:
    path: Path
    line: int
    end_line: int
    name: str
    has_comment: bool
    comment: str
    complexity_score: int

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


def previous_comment(lines: list[str], index: int) -> str:
    cursor = index - 1
    while cursor >= 0 and not lines[cursor].strip():
        cursor -= 1
    if cursor < 0:
        return ""
    line = lines[cursor].strip()
    if line.startswith("//"):
        comments: list[str] = []
        while cursor >= 0 and lines[cursor].strip().startswith("//"):
            comments.append(lines[cursor].strip())
            cursor -= 1
        return "\n".join(reversed(comments))
    if line.endswith("*/"):
        comments = []
        while cursor >= 0:
            comments.append(lines[cursor].strip())
            if lines[cursor].strip().startswith("/*"):
                return "\n".join(reversed(comments))
            cursor -= 1
    return ""


def has_nearby_comment(lines: list[str], index: int) -> bool:
    line = previous_significant_line(lines, index)
    return line.endswith("*/") or line.startswith("/*") or line.startswith("//")


def complexity_score(body: str) -> int:
    return (
        len(re.findall(r"\b(if|for|while|case|switch)\b", body))
        + len(re.findall(r"&&|\|\||\?", body))
    )


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
                    body = sanitized[index : end + 1]
                    definitions.append(
                        FunctionDefinition(
                            path,
                            start_line,
                            end_line,
                            name,
                            has_nearby_comment(lines, start_line - 1),
                            previous_comment(lines, start_line - 1),
                            complexity_score(body),
                        )
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
        if rel.suffix not in CHECKED_SUFFIXES:
            continue
        if any(rel == root or rel.is_relative_to(root) for root in CHECKED_ROOTS):
            files.append(path)
    return files


def has_module_comment(path: Path) -> bool:
    head = "\n".join(path.read_text(encoding="utf-8").splitlines()[:40])
    return all(field in head for field in MODULE_REQUIRED_FIELDS)


def is_documentation_target(definition: FunctionDefinition) -> bool:
    if definition.body_lines >= MIN_LARGE_FUNCTION_LINES:
        return True
    if (
        definition.body_lines >= MIN_COMPLEX_FUNCTION_LINES
        and definition.complexity_score >= MIN_COMPLEXITY_SCORE
    ):
        return True
    if definition.body_lines < MIN_RISK_FUNCTION_LINES:
        return False
    lower = definition.name.lower()
    return any(part in lower for part in CRITICAL_NAME_PARTS)


def normalize_comment(comment: str) -> str:
    text = re.sub(r"/\*+|\*/|//", " ", comment)
    text = re.sub(r"^\s*\*\s?", " ", text, flags=re.MULTILINE)
    return " ".join(text.lower().split())


def comment_quality_issue(definition: FunctionDefinition) -> str | None:
    normalized = normalize_comment(definition.comment)
    words = re.findall(r"[a-z0-9_]+", normalized)
    if len(words) < MIN_FUNCTION_COMMENT_WORDS:
        return "comment is too short to explain the contract"
    if normalized.count(".") == 0:
        return "comment should contain more than a label"
    if not any(term in normalized for term in COMMENT_DETAIL_TERMS):
        return "comment lacks validation, ownership, state, or boundary detail"
    if not any(term in normalized for term in COMMENT_CONTRACT_TERMS):
        return "comment lacks purpose, invariant, or failure-policy detail"
    return None


def allowlist_key(definition: FunctionDefinition) -> tuple[str, str]:
    return (str(definition.path.relative_to(ROOT)), definition.name)


def main() -> int:
    module_findings: list[Path] = []
    targets: list[FunctionDefinition] = []
    definitions_by_key: set[tuple[str, str]] = set()
    for path in checked_files():
        if not has_module_comment(path):
            module_findings.append(path)
        definitions = collect_definitions(path)
        definitions_by_key.update(allowlist_key(definition) for definition in definitions)
        targets.extend(definition for definition in definitions if is_documentation_target(definition))

    stale_allowlist = sorted(key for key in COMMENT_ALLOWLIST if key not in definitions_by_key)
    reviewed_targets = [
        definition for definition in targets if allowlist_key(definition) not in COMMENT_ALLOWLIST
    ]
    findings = [definition for definition in reviewed_targets if not definition.has_comment]
    weak_comments = [
        (definition, issue)
        for definition in reviewed_targets
        if definition.has_comment
        for issue in [comment_quality_issue(definition)]
        if issue is not None
    ]
    seen_comments: dict[str, FunctionDefinition] = {}
    duplicate_comments: list[tuple[FunctionDefinition, FunctionDefinition]] = []
    for definition in reviewed_targets:
        if not definition.has_comment:
            continue
        normalized = normalize_comment(definition.comment)
        previous = seen_comments.get(normalized)
        if previous is not None:
            duplicate_comments.append((previous, definition))
        else:
            seen_comments[normalized] = definition

    if module_findings or stale_allowlist or findings or weak_comments or duplicate_comments:
        print("error: source comment guardrail failed:", file=sys.stderr)
        if module_findings:
            print("missing module comments:", file=sys.stderr)
            for path in module_findings:
                print(f"  {path.relative_to(ROOT)}", file=sys.stderr)
        if stale_allowlist:
            print("stale comment allowlist entries:", file=sys.stderr)
            for path, name in stale_allowlist:
                print(f"  {path}: {name}", file=sys.stderr)
        if findings:
            print("missing function comments:", file=sys.stderr)
        for finding in findings:
            rel = finding.path.relative_to(ROOT)
            print(f"  {rel}:{finding.line}: {finding.name} ({finding.body_lines} lines)", file=sys.stderr)
        if weak_comments:
            print("weak function comments:", file=sys.stderr)
            for definition, issue in weak_comments:
                rel = definition.path.relative_to(ROOT)
                print(
                    f"  {rel}:{definition.line}: {definition.name} ({issue})",
                    file=sys.stderr,
                )
        if duplicate_comments:
            print("duplicate function comments:", file=sys.stderr)
            for first, second in duplicate_comments:
                first_rel = first.path.relative_to(ROOT)
                second_rel = second.path.relative_to(ROOT)
                print(
                    f"  {first_rel}:{first.line}: {first.name} duplicates "
                    f"{second_rel}:{second.line}: {second.name}",
                    file=sys.stderr,
                )
        return 1
    print(f"Source comment guardrail passed ({len(checked_files())} files, {len(targets)} functions).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
