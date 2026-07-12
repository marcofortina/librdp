#!/usr/bin/env python3
# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Verify Doxygen contracts for public C API declarations."""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INCLUDE = ROOT / "include" / "librdp"
CMAKE = ROOT / "CMakeLists.txt"


@dataclass(frozen=True)
class FunctionDecl:
    path: Path
    line: int
    return_type: str
    name: str
    params: list[tuple[str, str]]
    comment: str


@dataclass(frozen=True)
class TypeDecl:
    path: Path
    line: int
    kind: str
    name: str
    body: str
    comment: str


@dataclass(frozen=True)
class MacroDecl:
    path: Path
    line: int
    name: str
    line_text: str
    comment: str


DECL_RE = re.compile(
    r"(?m)^(?P<return>[A-Za-z_][A-Za-z0-9_\s\*]*?)\s+"
    r"(?P<name>librdp_[A-Za-z0-9_]+)\s*"
    r"\((?P<params>.*?)\)\s*;",
    re.S,
)
OPAQUE_OR_ALIAS_RE = re.compile(r"(?m)^typedef\s+(?:struct\s+)?[A-Za-z_][A-Za-z0-9_\s\*]*\s+(librdp_[A-Za-z0-9_]+)\s*;")
CALLBACK_RE = re.compile(r"(?m)^typedef\s+[A-Za-z_][A-Za-z0-9_\s\*]*\(\s*\*(librdp_[A-Za-z0-9_]+)\s*\)\s*\([^;]*\)\s*;")
MACRO_RE = re.compile(r"(?m)^#define\s+(LIBRDP_[A-Za-z0-9_]+)\b(?P<rest>.*)$")


def project_version() -> str:
    text = CMAKE.read_text(encoding="utf-8")
    match = re.search(r"project\s*\(\s*librdp\s+VERSION\s+([0-9]+\.[0-9]+\.[0-9]+)", text)
    if match is None:
        raise SystemExit("error: unable to find project version in CMakeLists.txt")
    return match.group(1)


def previous_comment(text: str, offset: int) -> str | None:
    cursor = offset
    while cursor > 0 and text[cursor - 1].isspace():
        cursor -= 1
    if cursor < 2 or text[cursor - 2 : cursor] != "*/":
        return None
    start = text.rfind("/**", 0, cursor - 2)
    if start < 0:
        return None
    between = text[start:cursor]
    return between


def split_params(params: str) -> list[str]:
    compact = " ".join(params.split())
    if compact == "void":
        return []
    return [item.strip() for item in params.split(",") if item.strip()]


def param_name(param: str) -> str:
    value = re.sub(r"\[[^\]]*\]", "", param.strip())
    value = value.replace("*", " ")
    parts = [part for part in value.split() if part not in {"const", "volatile", "restrict"}]
    return parts[-1] if parts else ""


def parse_params(params: str) -> list[tuple[str, str]]:
    parsed: list[tuple[str, str]] = []
    for param in split_params(params):
        name = param_name(param)
        if name:
            parsed.append((param, name))
    return parsed


def collect_declarations(path: Path) -> list[FunctionDecl]:
    text = path.read_text(encoding="utf-8")
    declarations: list[FunctionDecl] = []
    for match in DECL_RE.finditer(text):
        comment = previous_comment(text, match.start())
        if comment is None:
            comment = ""
        declarations.append(
            FunctionDecl(
                path=path,
                line=text.count("\n", 0, match.start()) + 1,
                return_type=" ".join(match.group("return").split()),
                name=match.group("name"),
                params=parse_params(match.group("params")),
                comment=comment,
            )
        )
    return declarations


def matching_brace(text: str, open_brace: int) -> int:
    depth = 0
    for index in range(open_brace, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    return -1


def collect_type_declarations(path: Path) -> list[TypeDecl]:
    text = path.read_text(encoding="utf-8")
    declarations: list[TypeDecl] = []
    covered: list[tuple[int, int]] = []
    for match in re.finditer(r"typedef\s+(enum|struct)\s+[A-Za-z0-9_]*\s*\{", text):
        open_brace = text.find("{", match.start(), match.end())
        close_brace = matching_brace(text, open_brace)
        if close_brace < 0:
            continue
        tail = re.match(r"\s*(librdp_[A-Za-z0-9_]+)\s*;", text[close_brace + 1 :])
        if tail is None:
            continue
        end = close_brace + 1 + tail.end()
        name = tail.group(1)
        comment = previous_comment(text, match.start()) or ""
        declarations.append(
            TypeDecl(
                path=path,
                line=text.count("\n", 0, match.start()) + 1,
                kind=match.group(1),
                name=name,
                body=text[open_brace + 1 : close_brace],
                comment=comment,
            )
        )
        covered.append((match.start(), end))

    def is_covered(offset: int) -> bool:
        return any(start <= offset < end for start, end in covered)

    for regex, kind in ((OPAQUE_OR_ALIAS_RE, "typedef"), (CALLBACK_RE, "callback")):
        for match in regex.finditer(text):
            if is_covered(match.start()):
                continue
            comment = previous_comment(text, match.start()) or ""
            declarations.append(
                TypeDecl(
                    path=path,
                    line=text.count("\n", 0, match.start()) + 1,
                    kind=kind,
                    name=match.group(1),
                    body="",
                    comment=comment,
                )
            )
    return declarations


def collect_macros(path: Path) -> list[MacroDecl]:
    text = path.read_text(encoding="utf-8")
    declarations: list[MacroDecl] = []
    for match in MACRO_RE.finditer(text):
        name = match.group(1)
        if name.endswith("_H"):
            continue
        declarations.append(
            MacroDecl(
                path=path,
                line=text.count("\n", 0, match.start()) + 1,
                name=name,
                line_text=match.group(0),
                comment=previous_comment(text, match.start()) or "",
            )
        )
    return declarations


def comment_param_block(comment: str, name: str) -> str:
    match = re.search(rf"@param\[(?:in|out|in,out)\]\s+{re.escape(name)}\b", comment)
    if match is None:
        return ""
    next_tag = re.search(r"\n\s*\*\s*@", comment[match.end() :])
    end = match.end() + next_tag.start() if next_tag is not None else len(comment)
    return comment[match.start() : end]


def pointer_like(type_text: str) -> bool:
    return "*" in type_text or type_text in {"librdp_event_callback"}


def validate(decl: FunctionDecl, version: str) -> list[str]:
    errors: list[str] = []
    location = f"{decl.path.relative_to(ROOT)}:{decl.line}: {decl.name}"
    comment = decl.comment

    if not comment:
        return [f"{location}: missing immediate Doxygen block"]
    if "@brief" not in comment:
        errors.append(f"{location}: missing @brief")
    if f"@since {version}" not in comment:
        errors.append(f"{location}: missing @since {version}")
    if "Thread-safety:" not in comment:
        errors.append(f"{location}: missing thread-safety note")

    for param_type, name in decl.params:
        block = comment_param_block(comment, name)
        if not block:
            errors.append(f"{location}: missing @param direction for {name}")
            continue
        if pointer_like(param_type) and "NULL" not in block:
            errors.append(f"{location}: parameter {name} lacks explicit NULL behavior")

    returns_void = decl.return_type.strip() == "void"
    if returns_void and "@return" in comment:
        errors.append(f"{location}: void function must not document @return")
    if not returns_void and "@return" not in comment:
        errors.append(f"{location}: non-void function missing @return")
    if "*" in decl.return_type and not re.search(r"\b(owned|owner|caller|internal|static storage)\b", comment):
        errors.append(f"{location}: pointer return lacks ownership/lifetime wording")
    return errors


def validate_type(decl: TypeDecl, version: str) -> list[str]:
    errors: list[str] = []
    location = f"{decl.path.relative_to(ROOT)}:{decl.line}: {decl.name}"
    if not decl.comment:
        return [f"{location}: missing immediate Doxygen block for public {decl.kind}"]
    if "@brief" not in decl.comment:
        errors.append(f"{location}: missing @brief")
    if f"@since {version}" not in decl.comment:
        errors.append(f"{location}: missing @since {version}")
    if decl.kind == "enum":
        for line_no, line in enumerate(decl.body.splitlines(), start=decl.line + 1):
            stripped = line.strip()
            if stripped.startswith("LIBRDP_") and "/**<" not in stripped:
                errors.append(f"{decl.path.relative_to(ROOT)}:{line_no}: enum value lacks inline Doxygen comment")
    if decl.kind == "struct":
        for line_no, line in enumerate(decl.body.splitlines(), start=decl.line + 1):
            stripped = line.strip()
            if not stripped or stripped in {"union", "{", "}"}:
                continue
            if stripped.endswith(";") and "/**<" not in stripped:
                errors.append(f"{decl.path.relative_to(ROOT)}:{line_no}: struct field lacks inline Doxygen comment")
    return errors


def validate_macro(decl: MacroDecl) -> list[str]:
    location = f"{decl.path.relative_to(ROOT)}:{decl.line}: {decl.name}"
    if "/**<" in decl.line_text or decl.comment:
        return []
    return [f"{location}: public macro lacks Doxygen comment"]


def main() -> int:
    version = project_version()
    declarations: list[FunctionDecl] = []
    types: list[TypeDecl] = []
    macros: list[MacroDecl] = []
    for header in sorted(INCLUDE.glob("*.h")):
        declarations.extend(collect_declarations(header))
        types.extend(collect_type_declarations(header))
        macros.extend(collect_macros(header))

    errors: list[str] = []
    for declaration in declarations:
        errors.extend(validate(declaration, version))
    for type_declaration in types:
        errors.extend(validate_type(type_declaration, version))
    for macro in macros:
        errors.extend(validate_macro(macro))

    if errors:
        print("error: public API documentation guardrail failed:", file=sys.stderr)
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        return 1
    print(
        "Public API documentation guardrail passed "
        f"({len(declarations)} functions, {len(types)} types, {len(macros)} macros)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
