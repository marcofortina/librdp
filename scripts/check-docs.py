#!/usr/bin/env python3
# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Validate required documentation, local links, and source consistency."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_MARKDOWN = (
    "README.md",
    "docs/index.md",
    "docs/build.md",
    "docs/contributing.md",
    "docs/coding-standards.md",
    "docs/api.md",
    "docs/api-reference.md",
    "docs/generated-api.md",
    "docs/programmers-reference.md",
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
    "docs/backend-guide.md",
    "docs/packaging.md",
    "docs/diagnostics.md",
    "docs/viewer-x11.md",
)
REQUIRED_FILES = REQUIRED_MARKDOWN + (
    "mkdocs.yml",
    "docs/requirements.txt",
    ".github/workflows/pages.yml",
    "docs/man/librdp.7",
    "docs/man/librdp-api.7",
    "docs/man/librdp-tracing.7",
    "docs/man/librdp-x11-viewer.1",
)
FORBIDDEN_DOCS = (
    "docs/roadmap.md",
    "docs/release.md",
)
LINK_RE = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
VIEWER_OPTION_RE = re.compile(r'"(--[a-z0-9-]+)"')
DOC_OPTION_RE = re.compile(r"--[a-z0-9-]+")
NON_VIEWER_OPTIONS = {
    "--build",
}
CMAKE_OPTION_RE = re.compile(r"option\((LIBRDP_BUILD_[A-Z0-9_]+)\b")
DOC_CMAKE_OPTION_RE = re.compile(r"LIBRDP_BUILD_[A-Z0-9_]+")
FUZZER_RE = re.compile(r"add_librdp_fuzzer\((fuzz_[a-z0-9_]+)\s+([^)]+_fuzzer\.c)\)")
PATH_IN_BACKTICKS_RE = re.compile(r"`([^`]+)`")
MANPAGE_RE = re.compile(r"^docs/man/(.+)\.(\d)$")
SEE_ALSO_RE = re.compile(r"\.BR\s+([A-Za-z0-9_.-]+)\s*\((\d)\)")
Doxygen_SETTING_RE = re.compile(r"^([A-Z0-9_]+)\s*=\s*(.*?)\s*$", re.MULTILINE)
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


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def markdown_files() -> list[str]:
    return sorted(str(path.relative_to(ROOT)) for path in (ROOT / "docs").glob("*.md"))


def viewer_source_options() -> set[str]:
    return set(VIEWER_OPTION_RE.findall(read("apps/x11-viewer/main.c")))


def documented_options(path: str) -> set[str]:
    return set(DOC_OPTION_RE.findall(read(path))) - NON_VIEWER_OPTIONS


def cmake_options() -> set[str]:
    return set(CMAKE_OPTION_RE.findall(read("CMakeLists.txt")))


def documented_cmake_options() -> set[str]:
    docs = "\n".join(read(rel) for rel in REQUIRED_MARKDOWN if rel != "README.md")
    return set(DOC_CMAKE_OPTION_RE.findall(docs))


def fuzz_targets() -> dict[str, str]:
    return {match.group(1): match.group(2) for match in FUZZER_RE.finditer(read("CMakeLists.txt"))}


def validate_protocol_rows(errors: list[str]) -> None:
    text = read("docs/protocol-support.md")
    for protocol in PROTOCOLS:
        if protocol not in text:
            errors.append(f"protocol missing from protocol-support.md: {protocol}")

    for line_no, line in enumerate(text.splitlines(), start=1):
        if not line.startswith("| MS-"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) < 4:
            errors.append(f"protocol row has too few columns at docs/protocol-support.md:{line_no}")
            continue
        for target in PATH_IN_BACKTICKS_RE.findall(line):
            if target.startswith("src/") or target.startswith("include/") or target.startswith("tests/") or target.startswith("fuzz/"):
                if "*" in target:
                    base = ROOT / target.split("*", 1)[0]
                    if not base.parent.exists():
                        errors.append(f"protocol row path parent missing at line {line_no}: {target}")
                elif not (ROOT / target).exists():
                    errors.append(f"protocol row path missing at line {line_no}: {target}")


def validate_viewer_options(errors: list[str]) -> None:
    source = viewer_source_options()
    viewer_doc = documented_options("docs/viewer-x11.md")
    manpage = documented_options("docs/man/librdp-x11-viewer.1")

    for option in sorted(source - viewer_doc):
        errors.append(f"viewer option missing from docs/viewer-x11.md: {option}")
    for option in sorted(source - manpage):
        errors.append(f"viewer option missing from docs/man/librdp-x11-viewer.1: {option}")
    for option in sorted((viewer_doc | manpage) - source):
        errors.append(f"documented viewer option not present in source: {option}")


def validate_cmake_options(errors: list[str]) -> None:
    source = cmake_options()
    documented = documented_cmake_options()
    for option in sorted(source - documented):
        errors.append(f"CMake option missing from docs: {option}")


def validate_fuzz_targets(errors: list[str]) -> None:
    targets = fuzz_targets()
    fuzzing_doc = read("docs/fuzzing.md")
    protocol_doc = read("docs/protocol-support.md")
    for target, source in sorted(targets.items()):
        if not (ROOT / source).exists():
            errors.append(f"fuzz target source missing in CMake: {target} {source}")
        stem = source.split("/", 1)[-1].replace("_fuzzer.c", "")
        if stem not in fuzzing_doc and source not in protocol_doc:
            errors.append(f"fuzz target not referenced by docs: {target}")


def manpage_index() -> set[tuple[str, str]]:
    index: set[tuple[str, str]] = set()
    for path in (ROOT / "docs/man").glob("*.[0-9]"):
        rel = str(path.relative_to(ROOT))
        match = MANPAGE_RE.match(rel)
        if match:
            index.add((match.group(1), match.group(2)))
    return index


def validate_manpages(errors: list[str]) -> None:
    index = manpage_index()
    for rel in REQUIRED_FILES:
        match = MANPAGE_RE.match(rel)
        if match and (match.group(1), match.group(2)) not in index:
            errors.append(f"required manpage missing: {rel}")

    for path in sorted((ROOT / "docs/man").glob("*.[0-9]")):
        text = path.read_text(encoding="utf-8")
        for name, section in SEE_ALSO_RE.findall(text):
            if (name, section) not in index:
                errors.append(f"unresolved SEE ALSO in {path.relative_to(ROOT)}: {name}({section})")


def validate_public_headers(errors: list[str]) -> None:
    api_reference = read("docs/api-reference.md")
    umbrella = read("include/librdp/librdp.h")
    for path in sorted((ROOT / "include/librdp").glob("*.h")):
        rel = str(path.relative_to(ROOT))
        include_name = f"<librdp/{path.name}>"
        if rel not in api_reference and include_name not in api_reference:
            errors.append(f"public header missing from api-reference.md: {rel}")
        if path.name != "librdp.h" and include_name not in umbrella:
            errors.append(f"public header missing from umbrella header: {include_name}")
        header_text = path.read_text(encoding="utf-8")
        if "@defgroup" not in header_text:
            errors.append(f"public header missing Doxygen group: {rel}")
        if "/** @} */" not in header_text:
            errors.append(f"public header missing Doxygen group close: {rel}")


def doxygen_settings() -> dict[str, str]:
    return {match.group(1): match.group(2).strip() for match in Doxygen_SETTING_RE.finditer(read("Doxyfile"))}


def validate_doxygen_config(errors: list[str]) -> None:
    settings = doxygen_settings()
    expected = {
        "GENERATE_HTML": "YES",
        "GENERATE_XML": "YES",
        "HAVE_DOT": "NO",
        "CLASS_GRAPH": "NO",
        "COLLABORATION_GRAPH": "NO",
        "DIRECTORY_GRAPH": "NO",
        "INCLUDE_GRAPH": "NO",
        "INCLUDED_BY_GRAPH": "NO",
        "WARN_AS_ERROR": "YES",
        "WARN_IF_UNDOCUMENTED": "YES",
        "WARN_IF_DOC_ERROR": "YES",
        "USE_MDFILE_AS_MAINPAGE": "docs/api-reference.md",
    }
    for key, value in expected.items():
        if settings.get(key) != value:
            errors.append(f"Doxyfile {key} must be {value}")
    inputs = settings.get("INPUT", "")
    for required_input in ("include/librdp", "docs/api-reference.md"):
        if required_input not in inputs:
            errors.append(f"Doxyfile INPUT missing {required_input}")


def validate_mkdocs(errors: list[str]) -> None:
    config = read("mkdocs.yml")
    required_snippets = (
        "site_name: librdp",
        "strict: true",
        "theme:",
        "name: material",
        "docs_dir: docs",
        "site_dir: _site",
    )
    for snippet in required_snippets:
        if snippet not in config:
            errors.append(f"mkdocs.yml missing required setting: {snippet}")
    for rel in REQUIRED_MARKDOWN:
        if rel == "README.md":
            continue
        nav_name = rel.removeprefix("docs/")
        if nav_name not in config:
            errors.append(f"mkdocs.yml nav missing document: {nav_name}")


def validate_pages_workflow(errors: list[str]) -> None:
    workflow = read(".github/workflows/pages.yml")
    required_snippets = (
        "actions/deploy-pages@v4",
        "actions/upload-pages-artifact@v3",
        "python3 scripts/check-docs.py",
        "python3 scripts/check-public-api-docs.py",
        "python3 scripts/check-doxygen.py",
        "mkdocs build --strict --site-dir _site",
        "build/doxygen/html",
    )
    for snippet in required_snippets:
        if snippet not in workflow:
            errors.append(f"pages workflow missing required step content: {snippet}")


def validate_generated_api_page(errors: list[str]) -> None:
    page = read("docs/generated-api.md")
    link = "https://marcofortina.github.io/librdp/api/doxygen/html/index.html"
    if link not in page:
        errors.append("generated API page missing published Doxygen link")
    if "api/doxygen/html/" not in read("docs/index.md"):
        errors.append("documentation home missing generated Doxygen publish path")
    if "generated-api.md" not in read("mkdocs.yml"):
        errors.append("mkdocs.yml missing generated API page")


def main() -> int:
    errors: list[str] = []
    required_set = set(REQUIRED_MARKDOWN)
    readme_links = required_doc_links_from_readme()
    docs_files = markdown_files()

    for rel in FORBIDDEN_DOCS:
        if (ROOT / rel).exists():
            errors.append(f"forbidden planning document present: {rel}")

    for rel in docs_files:
        if rel not in required_set:
            errors.append(f"unregistered document: {rel}")
        if rel not in readme_links:
            errors.append(f"document not linked from README.md: {rel}")

    for rel in REQUIRED_FILES:
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

    validate_protocol_rows(errors)
    validate_viewer_options(errors)
    validate_cmake_options(errors)
    validate_fuzz_targets(errors)
    validate_manpages(errors)
    validate_public_headers(errors)
    validate_doxygen_config(errors)
    validate_mkdocs(errors)
    validate_pages_workflow(errors)
    validate_generated_api_page(errors)

    if errors:
        print("error: documentation guardrail failed:", file=sys.stderr)
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        return 1
    print(f"Documentation guardrail passed ({len(REQUIRED_FILES)} files).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
