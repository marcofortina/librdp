#!/usr/bin/env python3
# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Validate required Markdown documentation and local links."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REQUIRED = (
    "README.md",
    "docs/build.md",
    "docs/contributing.md",
    "docs/coding-standards.md",
    "docs/api.md",
    "docs/examples.md",
    "docs/abi-versioning.md",
    "docs/architecture.md",
    "docs/portability.md",
    "docs/protocol-support.md",
    "docs/security.md",
    "docs/tracing.md",
    "docs/testing.md",
    "docs/fuzzing.md",
    "docs/backends.md",
    "docs/packaging.md",
    "docs/diagnostics.md",
    "docs/viewer-x11.md",
)
LINK_RE = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
DISALLOWED_PHRASES = (
    "Source complete",
    "source complete",
    "target validation",
    "Target validation",
    "validation status",
    "Validation status",
    "validation required",
    "Validation required",
    "smoke test",
    "Smoke test",
    "smoke tests",
    "Smoke tests",
)
PROTOCOLS = (
    "MS-RDPBCGR",
    "MS-RDPEGFX",
    "MS-RDPRFX",
    "MS-RDPNSC",
    "MS-RDPEGDI",
    "MS-RDPEDISP",
    "MS-RDPEDYC",
    "MS-RDPEMT",
    "MS-RDPEUDP",
    "MS-RDPEUDP2",
    "MS-RDPECLIP",
    "MS-RDPEI",
    "MS-RDPECI",
    "MS-RDPEA",
    "MS-RDPEAI",
    "MS-RDPEV",
    "MS-RDPEVOR",
    "MS-RDPDR",
    "MS-RDPEFS",
    "MS-RDPESP",
    "MS-RDPEPC",
    "MS-RDPEUSB",
    "MS-RDPEPNP",
    "MS-RDPERP",
    "MS-RDPEXPS",
    "MS-RDPELE",
    "MS-RDPEMC",
    "MS-RDPET",
    "MS-RDPEAR",
    "MS-RDPESC",
    "MS-RDPCR2",
    "MS-RDPEDC",
    "MS-RDPEPS",
    "MS-RDPECAM",
    "MS-RDPEECO",
    "MS-RDPEWA",
)


def has_required_header(path: Path) -> bool:
    prefix = path.read_text(encoding="utf-8")[:512]
    return "Copyright (C) 2026 Marco Fortina" in prefix and "SPDX-License-Identifier: AGPL-3.0-or-later" in prefix


def link_target_exists(path: Path, target: str) -> bool:
    if "://" in target or target.startswith("mailto:"):
        return True
    clean = target.split("#", 1)[0]
    if not clean:
        return True
    return (path.parent / clean).resolve().exists()


def local_links(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    return [match.group(1).strip().split("#", 1)[0] for match in LINK_RE.finditer(text)]


def required_doc_links_from_readme() -> set[str]:
    readme = ROOT / "README.md"
    links: set[str] = set()
    for target in local_links(readme):
        if target:
            links.add(str((readme.parent / target).resolve().relative_to(ROOT)))
    return links


def main() -> int:
    errors: list[str] = []
    required_set = set(REQUIRED)
    readme_links = required_doc_links_from_readme()
    docs_files = sorted(str(path.relative_to(ROOT)) for path in (ROOT / "docs").glob("*.md"))

    for rel in docs_files:
        if rel not in required_set:
            errors.append(f"unregistered document: {rel}")
        if rel not in readme_links:
            errors.append(f"document not linked from README.md: {rel}")

    for rel in REQUIRED:
        path = ROOT / rel
        if not path.is_file():
            errors.append(f"missing required document: {rel}")
            continue
        if not has_required_header(path):
            errors.append(f"missing document header: {rel}")
        text = path.read_text(encoding="utf-8")
        for phrase in DISALLOWED_PHRASES:
            if phrase in text:
                errors.append(f"disallowed documentation phrase in {rel}: {phrase}")
        for match in LINK_RE.finditer(text):
            target = match.group(1).strip()
            if not link_target_exists(path, target):
                errors.append(f"broken link in {rel}: {target}")

    protocol_doc = (ROOT / "docs/protocol-support.md").read_text(encoding="utf-8")
    for protocol in PROTOCOLS:
        if protocol not in protocol_doc:
            errors.append(f"protocol missing from protocol-support.md: {protocol}")

    if errors:
        print("error: documentation guardrail failed:", file=sys.stderr)
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        return 1
    print(f"Documentation guardrail passed ({len(REQUIRED)} files).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
