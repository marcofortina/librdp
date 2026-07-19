#!/usr/bin/env python3
# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Generate and validate a CycloneDX JSON SBOM for a configured build tree."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CYCLONEDX_SPEC = "1.5"
TOOL_VERSION = "0.1.0"
OPTIONAL_FEATURES = (
    ("ffmpeg-avc", "LIBRDP_WITH_FFMPEG_AVC", "LIBRDP_FFMPEG_AVC", ("libavcodec", "libavutil", "libswscale")),
    ("openh264-avc", "LIBRDP_WITH_OPENH264_AVC", "LIBRDP_OPENH264_AVC", ("openh264",)),
    ("pcsc", "LIBRDP_WITH_PCSC", "LIBRDP_PCSC", ("libpcsclite",)),
    ("libusb", "LIBRDP_WITH_LIBUSB", "LIBRDP_LIBUSB", ("libusb-1.0",)),
    ("fido2", "LIBRDP_WITH_FIDO2", "LIBRDP_FIDO2", ("libfido2",)),
    ("cbor", "LIBRDP_WITH_CBOR", "LIBRDP_CBOR", ("libcbor",)),
    ("cups", "LIBRDP_WITH_CUPS", "LIBRDP_CUPS", ("cups",)),
    ("acl", "LIBRDP_WITH_ACL", "LIBRDP_ACL", ("libacl",)),
    ("attr", "LIBRDP_WITH_ATTR", "LIBRDP_ATTR", ("libattr",)),
    ("archive", "LIBRDP_WITH_ARCHIVE", "LIBRDP_ARCHIVE", ("libarchive",)),
    ("pipewire", "LIBRDP_WITH_PIPEWIRE", "LIBRDP_PIPEWIRE", ("libpipewire-0.3",)),
    ("jpeg", "LIBRDP_WITH_JPEG", "LIBRDP_JPEG", ("libjpeg",)),
    ("xshm", "LIBRDP_WITH_XSHM", "LIBRDP_XSHM", ("xext",)),
    ("xrandr", "LIBRDP_WITH_XRANDR", "LIBRDP_XRANDR", ("xrandr",)),
)
BUILD_OPTIONS = (
    "LIBRDP_ABI_VERSION",
    "LIBRDP_BUILD_EXAMPLES",
    "LIBRDP_BUILD_FUZZ",
    "LIBRDP_BUILD_TESTS",
    "LIBRDP_BUILD_ADMIN",
    "LIBRDP_BUILD_SERVER",
    "LIBRDP_BUILD_VIEWER",
    "LIBRDP_BUILD_WORKSPACE",
    "LIBRDP_ENABLE_SANITIZERS",
    "LIBRDP_ENABLE_WERROR",
    "LIBRDP_LIBRARY_TYPE",
)
ARTIFACT_PATTERNS = (
    "liblibrdp*",
    "librdp-admin",
    "librdp-server",
    "librdp-session-agent",
    "librdp-session-broker",
    "librdp-session-supervisor",
    "librdp-viewer",
    "librdp-workspace",
    "librdp-example-*",
    "test_*",
    "librdp.pc",
    "librdpConfig*.cmake",
)
APPLICATION_ARTIFACTS = (
    ("LIBRDP_BUILD_ADMIN", "librdp-admin"),
    ("LIBRDP_BUILD_SERVER", "librdp-server"),
    ("LIBRDP_BUILD_VIEWER", "librdp-viewer"),
    ("LIBRDP_BUILD_WORKSPACE", "librdp-workspace"),
)
INSTALL_DIR_DEFAULTS = {
    "CMAKE_INSTALL_BINDIR": "bin",
    "CMAKE_INSTALL_SBINDIR": "sbin",
    "CMAKE_INSTALL_LIBEXECDIR": "libexec",
    "CMAKE_INSTALL_DATADIR": "share",
}
CACHE_RE = re.compile(r"^([^:#][^:]*):([^=]+)=(.*)$")


def read_cache(cache_path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in cache_path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = CACHE_RE.match(line)
        if match:
            values[match.group(1)] = match.group(3)
    return values


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_files(source_dir: Path) -> list[Path]:
    git = shutil.which("git")
    if git and (source_dir / ".git").exists():
        result = subprocess.run(
            [git, "ls-files"],
            cwd=source_dir,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if result.returncode == 0:
            return sorted(source_dir / line for line in result.stdout.splitlines() if line and (source_dir / line).exists())

    excluded = {".git", "__pycache__", "build"}
    files: list[Path] = []
    for path in source_dir.rglob("*"):
        if not path.is_file():
            continue
        rel_parts = path.relative_to(source_dir).parts
        if any(part in excluded or part.startswith("build-") for part in rel_parts):
            continue
        files.append(path)
    return sorted(files)


def source_tree_hash(source_dir: Path) -> str:
    digest = hashlib.sha256()
    for path in source_files(source_dir):
        rel = path.relative_to(source_dir).as_posix()
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        digest.update(sha256_file(path).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def build_artifacts(build_dir: Path) -> list[Path]:
    artifacts: set[Path] = set()
    for pattern in ARTIFACT_PATTERNS:
        for path in build_dir.glob(pattern):
            if path.is_file():
                artifacts.add(path)
    return sorted(artifacts, key=lambda item: item.relative_to(build_dir).as_posix())


def bool_cache(value: str | None) -> str:
    if value is None or value == "":
        return "false"
    return "true" if value in {"1", "ON", "TRUE", "YES", "Y"} else "false"


def feature_found(cache: dict[str, str], prefix: str) -> bool:
    if bool_cache(cache.get(f"{prefix}_FOUND")) == "true":
        return True
    if prefix == "LIBRDP_CUPS":
        library = cache.get("LIBRDP_CUPS_LIBRARY", "")
        return bool(library) and not library.endswith("-NOTFOUND")
    return False


def property_entry(name: str, value: object) -> dict[str, str]:
    return {"name": name, "value": str(value)}


def application_backend(cache: dict[str, str]) -> str:
    if cache.get("CMAKE_SYSTEM_NAME") == "Darwin":
        return "cocoa"
    if cache.get("CMAKE_SYSTEM_NAME") in {
        "Linux",
        "FreeBSD",
        "OpenBSD",
        "NetBSD",
        "SunOS",
    }:
        return "x11"
    return "none"


def install_path(cache: dict[str, str], directory_name: str, *parts: str) -> str:
    directory = cache.get(directory_name) or INSTALL_DIR_DEFAULTS[directory_name]
    if os.path.isabs(directory):
        root = Path(directory)
    else:
        root = Path(cache.get("CMAKE_INSTALL_PREFIX") or "/usr/local") / directory
    return str(root.joinpath(*parts))


def install_properties(cache: dict[str, str]) -> list[dict[str, str]]:
    properties = [
        property_entry(
            "librdp:install:application-directory",
            install_path(cache, "CMAKE_INSTALL_BINDIR"),
        )
    ]
    if (
        application_backend(cache) == "x11"
        and bool_cache(cache.get("LIBRDP_BUILD_SERVER")) == "true"
    ):
        properties.extend(
            (
                property_entry(
                    "librdp:install:session-broker",
                    install_path(
                        cache,
                        "CMAKE_INSTALL_SBINDIR",
                        "librdp-session-broker",
                    ),
                ),
                property_entry(
                    "librdp:install:session-agent",
                    install_path(
                        cache,
                        "CMAKE_INSTALL_LIBEXECDIR",
                        "librdp",
                        "librdp-session-agent",
                    ),
                ),
                property_entry(
                    "librdp:install:session-supervisor",
                    install_path(
                        cache,
                        "CMAKE_INSTALL_LIBEXECDIR",
                        "librdp",
                        "librdp-session-supervisor",
                    ),
                ),
                property_entry(
                    "librdp:install:session-broker-config-example",
                    install_path(
                        cache,
                        "CMAKE_INSTALL_DATADIR",
                        "librdp",
                        "librdp-session-broker.conf.example",
                    ),
                ),
            )
        )
    return properties


def created_timestamp() -> str:
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch:
        try:
            value = int(epoch)
        except ValueError:
            value = 0
        return dt.datetime.fromtimestamp(value, tz=dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def dependency_components(cache: dict[str, str]) -> tuple[list[dict[str, object]], list[str]]:
    components: list[dict[str, object]] = []
    refs: list[str] = []
    seen: set[str] = set()

    def dependency_path(prefix: str, module: str) -> str:
        candidates = {module.lower(), module.lower().replace("-", "_").replace(".", "_")}
        if module.startswith("lib"):
            stripped = module[3:]
            candidates.add(stripped.lower())
            candidates.add(stripped.lower().replace("-", "_").replace(".", "_"))
        prefix_marker = f"pkgcfg_lib_{prefix.lower()}_"
        for key, value in sorted(cache.items()):
            key_lower = key.lower()
            if key_lower.startswith(prefix_marker):
                suffix = key_lower[len(prefix_marker):]
                if any(candidate in suffix for candidate in candidates):
                    return value
        if prefix == "LIBRDP_CUPS":
            return cache.get("LIBRDP_CUPS_LIBRARY", "")
        if prefix == "LIBRDP_XSHM":
            return cache.get("X11_Xext_LIB", "")
        if prefix == "LIBRDP_XRANDR":
            return cache.get("X11_Xrandr_LIB", "")
        return ""

    def add_dependency(name: str, version: str = "", path: str = "", scope: str = "required") -> None:
        key = name.lower()
        if key in seen:
            return
        seen.add(key)
        ref = f"dependency:{key}"
        component: dict[str, object] = {
            "type": "library",
            "bom-ref": ref,
            "name": name,
            "scope": scope,
            "properties": [],
        }
        if version:
            component["version"] = version
        properties = component["properties"]
        assert isinstance(properties, list)
        if path and not path.endswith("-NOTFOUND"):
            properties.append(property_entry("librdp:linked-path", path))
            path_obj = Path(path)
            if path_obj.is_file():
                component["hashes"] = [{"alg": "SHA-256", "content": sha256_file(path_obj)}]
        components.append(component)
        refs.append(ref)

    add_dependency("openssl", cache.get("_OPENSSL_VERSION", ""), cache.get("OPENSSL_SSL_LIBRARY", ""))
    add_dependency("openssl-crypto", cache.get("_OPENSSL_VERSION", ""), cache.get("OPENSSL_CRYPTO_LIBRARY", ""))
    if cache.get("Iconv_IS_BUILT_IN") == "1":
        add_dependency("iconv", "", "built-in")
    else:
        add_dependency("iconv", "", cache.get("Iconv_LIBRARY", ""))

    for feature_name, _option, prefix, modules in OPTIONAL_FEATURES:
        if not feature_found(cache, prefix):
            continue
        for module in modules:
            version = cache.get(f"{prefix}_{module}_VERSION", "") or cache.get(f"{prefix}_VERSION", "")
            path = dependency_path(prefix, module)
            add_dependency(module, version, path, f"optional:{feature_name}")

    return components, refs


def feature_properties(cache: dict[str, str]) -> list[dict[str, str]]:
    properties = [
        property_entry("librdp:application-backend", application_backend(cache))
    ]
    for name in BUILD_OPTIONS:
        properties.append(property_entry(f"librdp:cmake:{name}", cache.get(name, "")))
    for feature_name, option, prefix, _modules in OPTIONAL_FEATURES:
        properties.append(property_entry(f"librdp:feature:{feature_name}:requested", cache.get(option, "AUTO")))
        properties.append(property_entry(f"librdp:feature:{feature_name}:found", "true" if feature_found(cache, prefix) else "false"))
    return properties + install_properties(cache)


def artifact_components(build_dir: Path) -> tuple[list[dict[str, object]], list[str]]:
    components: list[dict[str, object]] = []
    refs: list[str] = []
    for path in build_artifacts(build_dir):
        rel = path.relative_to(build_dir).as_posix()
        ref = f"artifact:{rel}"
        components.append(
            {
                "type": "file",
                "bom-ref": ref,
                "name": rel,
                "hashes": [{"alg": "SHA-256", "content": sha256_file(path)}],
                "properties": [
                    property_entry("librdp:artifact:path", rel),
                    property_entry("librdp:artifact:size", path.stat().st_size),
                ],
            }
        )
        refs.append(ref)
    return components, refs


def generate_bom(source_dir: Path, build_dir: Path) -> dict[str, object]:
    cache_path = build_dir / "CMakeCache.txt"
    if not cache_path.is_file():
        raise RuntimeError(f"CMake cache not found: {cache_path}")
    cache = read_cache(cache_path)
    source_hash = source_tree_hash(source_dir)
    dependency_items, dependency_refs = dependency_components(cache)
    artifact_items, artifact_refs = artifact_components(build_dir)
    project_version = cache.get("CMAKE_PROJECT_VERSION", "0.0.0")
    compiler = cache.get("CMAKE_C_COMPILER", "")
    serial_seed = f"{source_hash}:{build_dir.resolve()}:{project_version}"

    root_component: dict[str, object] = {
        "type": "library",
        "bom-ref": "library:librdp",
        "name": "librdp",
        "version": project_version,
        "hashes": [{"alg": "SHA-256", "content": source_hash}],
        "properties": [
            property_entry("librdp:source-hash", source_hash),
            property_entry("librdp:source-dir", source_dir.resolve()),
            property_entry("librdp:build-dir", build_dir.resolve()),
            property_entry("librdp:compiler", compiler),
        ]
        + feature_properties(cache),
    }

    bom: dict[str, object] = {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC,
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, serial_seed)}",
        "version": 1,
        "metadata": {
            "timestamp": created_timestamp(),
            "tools": [{"vendor": "librdp", "name": "generate-sbom", "version": TOOL_VERSION}],
            "component": root_component,
            "properties": [
                property_entry("librdp:cmake-cache-sha256", sha256_file(cache_path)),
                property_entry("librdp:artifact-count", len(artifact_refs)),
                property_entry("librdp:dependency-count", len(dependency_refs)),
            ],
        },
        "components": dependency_items + artifact_items,
        "dependencies": [
            {
                "ref": "library:librdp",
                "dependsOn": dependency_refs + artifact_refs,
            }
        ],
    }
    validate_bom(bom)
    return bom


def load_json(path: Path) -> dict[str, object]:
    with path.open("r", encoding="utf-8") as handle:
        loaded = json.load(handle)
    if not isinstance(loaded, dict):
        raise RuntimeError("SBOM root must be a JSON object")
    return loaded


def require(condition: bool, errors: list[str], message: str) -> None:
    if not condition:
        errors.append(message)


def validate_hashes(component: dict[str, object], errors: list[str], where: str) -> None:
    hashes = component.get("hashes", [])
    require(isinstance(hashes, list) and bool(hashes), errors, f"{where}: missing hashes")
    for entry in hashes if isinstance(hashes, list) else []:
        require(isinstance(entry, dict), errors, f"{where}: hash entry is not an object")
        if not isinstance(entry, dict):
            continue
        require(entry.get("alg") == "SHA-256", errors, f"{where}: unsupported hash algorithm")
        content = entry.get("content")
        require(isinstance(content, str) and re.fullmatch(r"[0-9a-f]{64}", content) is not None,
                errors,
                f"{where}: invalid SHA-256 content")


def component_properties(component: dict[str, object]) -> dict[str, str]:
    properties = component.get("properties", [])
    if not isinstance(properties, list):
        return {}
    return {
        item["name"]: str(item.get("value", ""))
        for item in properties
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }


def validate_bom(bom: dict[str, object]) -> None:
    errors: list[str] = []
    require(bom.get("bomFormat") == "CycloneDX", errors, "bomFormat must be CycloneDX")
    require(bom.get("specVersion") == CYCLONEDX_SPEC, errors, "unsupported CycloneDX specVersion")
    require(isinstance(bom.get("serialNumber"), str), errors, "serialNumber missing")
    metadata = bom.get("metadata")
    require(isinstance(metadata, dict), errors, "metadata missing")
    components = bom.get("components")
    require(isinstance(components, list), errors, "components missing")
    dependencies = bom.get("dependencies")
    require(isinstance(dependencies, list), errors, "dependencies missing")
    if not isinstance(metadata, dict) or not isinstance(components, list) or not isinstance(dependencies, list):
        raise RuntimeError("; ".join(errors))

    root = metadata.get("component")
    require(isinstance(root, dict), errors, "metadata.component missing")
    refs: set[str] = set()
    if isinstance(root, dict):
        require(root.get("bom-ref") == "library:librdp", errors, "root component reference mismatch")
        require(root.get("name") == "librdp", errors, "root component name mismatch")
        validate_hashes(root, errors, "root component")
        refs.add("library:librdp")
        root_properties = root.get("properties", [])
        require(isinstance(root_properties, list), errors, "root properties missing")
        property_names = {item.get("name") for item in root_properties if isinstance(item, dict)}
        properties_by_name = component_properties(root)
        require("librdp:source-hash" in property_names, errors, "source hash property missing")
        require("librdp:compiler" in property_names, errors, "compiler property missing")
        require("librdp:application-backend" in property_names,
                errors,
                "application backend property missing")
        require("librdp:install:application-directory" in property_names,
                errors,
                "application install directory property missing")
        for option_name in BUILD_OPTIONS:
            require(f"librdp:cmake:{option_name}" in property_names,
                    errors,
                    f"build option property missing: {option_name}")
        for feature_name, _option, _prefix, _modules in OPTIONAL_FEATURES:
            require(f"librdp:feature:{feature_name}:requested" in property_names,
                    errors,
                    f"feature requested property missing: {feature_name}")
            require(f"librdp:feature:{feature_name}:found" in property_names,
                    errors,
                    f"feature found property missing: {feature_name}")
        if (properties_by_name.get("librdp:application-backend") == "x11" and
                bool_cache(properties_by_name.get("librdp:cmake:LIBRDP_BUILD_SERVER")) == "true"):
            for property_name in (
                "librdp:install:session-broker",
                "librdp:install:session-agent",
                "librdp:install:session-supervisor",
                "librdp:install:session-broker-config-example",
            ):
                require(property_name in property_names,
                        errors,
                        f"managed-session install property missing: {property_name}")

    component_names: set[str] = set()
    for index, component in enumerate(components):
        require(isinstance(component, dict), errors, f"component {index}: not an object")
        if not isinstance(component, dict):
            continue
        ref = component.get("bom-ref")
        require(isinstance(ref, str) and bool(ref), errors, f"component {index}: bom-ref missing")
        if isinstance(ref, str):
            require(ref not in refs, errors, f"duplicate bom-ref: {ref}")
            refs.add(ref)
        require(component.get("type") in {"library", "file"}, errors, f"component {index}: invalid type")
        require(isinstance(component.get("name"), str) and bool(component.get("name")),
                errors,
                f"component {index}: name missing")
        if isinstance(component.get("name"), str):
            component_names.add(str(component["name"]))
        component_type = component.get("type")
        properties = component_properties(component)
        linked_path = properties.get("librdp:linked-path", "")
        if component_type == "file" or (linked_path and linked_path != "built-in"):
            validate_hashes(component, errors, f"component {index}")

    if isinstance(root, dict):
        root_properties = component_properties(root)
        for option_name, artifact_name in APPLICATION_ARTIFACTS:
            if bool_cache(root_properties.get(f"librdp:cmake:{option_name}")) == "true":
                require(artifact_name in component_names,
                        errors,
                        f"requested application artifact missing: {artifact_name}")
        if (root_properties.get("librdp:application-backend") == "x11" and
                bool_cache(root_properties.get("librdp:cmake:LIBRDP_BUILD_SERVER")) == "true"):
            for artifact_name in (
                "librdp-session-agent",
                "librdp-session-broker",
                "librdp-session-supervisor",
            ):
                require(artifact_name in component_names,
                        errors,
                        f"managed-session artifact missing: {artifact_name}")

    dependency_refs: set[str] = set()
    for entry in dependencies:
        require(isinstance(entry, dict), errors, "dependency entry is not an object")
        if not isinstance(entry, dict):
            continue
        ref = entry.get("ref")
        require(isinstance(ref, str) and ref in refs, errors, f"dependency ref invalid: {ref}")
        depends_on = entry.get("dependsOn")
        require(isinstance(depends_on, list), errors, f"dependency dependsOn invalid: {ref}")
        if isinstance(depends_on, list):
            for dependency_ref in depends_on:
                require(isinstance(dependency_ref, str) and dependency_ref in refs,
                        errors,
                        f"dependency target invalid: {dependency_ref}")
                if isinstance(dependency_ref, str):
                    dependency_refs.add(dependency_ref)
    require(bool(dependency_refs), errors, "root dependency list is empty")

    if errors:
        raise RuntimeError("; ".join(errors))


def write_bom(path: Path, bom: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(bom, indent=2, sort_keys=True)
    path.write_text(text + "\n", encoding="utf-8")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate or validate a CycloneDX SBOM for a librdp build")
    parser.add_argument("--source-dir", type=Path, default=ROOT)
    parser.add_argument("--build-dir", type=Path, default=ROOT / "build")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--validate", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        if args.validate:
            validate_bom(load_json(args.validate))
            return 0
        if not args.output:
            raise RuntimeError("--output is required when not validating an existing SBOM")
        bom = generate_bom(args.source_dir.resolve(), args.build_dir.resolve())
        write_bom(args.output, bom)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
