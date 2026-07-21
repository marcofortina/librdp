#!/usr/bin/env python3
# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Validate installed application and managed-session privilege boundaries."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys


def staged_path(destdir: Path, logical_path: Path) -> Path:
    if not logical_path.is_absolute():
        raise ValueError(f"install path is not absolute: {logical_path}")
    return destdir / logical_path.relative_to(logical_path.anchor)


def executable(path: Path) -> None:
    info = path.stat()
    mode = stat.S_IMODE(info.st_mode)
    if not stat.S_ISREG(info.st_mode):
        raise RuntimeError(f"installed path is not a regular file: {path}")
    if mode & 0o111 == 0:
        raise RuntimeError(f"installed path is not executable: {path}")
    if mode & (stat.S_ISUID | stat.S_ISGID):
        raise RuntimeError(f"installed path has elevated mode bits: {path}")


def check_configured_paths(
    broker: Path,
    environment: dict[str, str],
    supervisor: Path,
    agent: Path,
) -> None:
    invalid = subprocess.run(
        [str(broker), "--desktop", "/bin/true", "--check-config"],
        check=False,
        env=environment,
        capture_output=True,
        text=True,
    )
    if invalid.returncode != 2 or "event=config.failed" not in invalid.stderr:
        raise RuntimeError(
            "installed broker did not reject an incomplete policy cleanly"
        )
    result = subprocess.run(
        [
            str(broker),
            "--desktop",
            "/bin/true",
            "--security",
            "standard",
            "--allow-standard-security",
            "--check-config",
        ],
        check=True,
        env=environment,
        capture_output=True,
        text=True,
    )
    expected = f"supervisor={supervisor} agent={agent}"
    if expected not in result.stdout:
        raise RuntimeError(
            f"installed broker reported unexpected helper paths: "
            f"{result.stdout.strip()}"
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cmake", required=True)
    parser.add_argument("--build-dir", required=True, type=Path)
    parser.add_argument("--destdir", required=True, type=Path)
    parser.add_argument("--bindir", required=True, type=Path)
    parser.add_argument("--sbindir", required=True, type=Path)
    parser.add_argument("--libdir", required=True, type=Path)
    parser.add_argument("--libexecdir", required=True, type=Path)
    parser.add_argument("--datadir", required=True, type=Path)
    parser.add_argument("--mandir", required=True, type=Path)
    parser.add_argument(
        "--application",
        action="append",
        choices=(
            "librdp-admin",
            "librdp-server",
            "librdp-viewer",
            "librdp-workspace",
        ),
        default=[],
    )
    parser.add_argument("--config", default="", nargs="?")
    args = parser.parse_args()

    shutil.rmtree(args.destdir, ignore_errors=True)
    environment = os.environ.copy()
    environment["DESTDIR"] = str(args.destdir)
    command = [args.cmake, "--install", str(args.build_dir)]
    if args.config:
        command.extend(["--config", args.config])
    subprocess.run(command, check=True, env=environment)

    applications = tuple(
        staged_path(args.destdir, args.bindir / name)
        for name in args.application
    )
    broker = staged_path(
        args.destdir, args.sbindir / "librdp-session-broker"
    )
    agent = staged_path(
        args.destdir, args.libexecdir / "librdp-session-agent"
    )
    supervisor = staged_path(
        args.destdir, args.libexecdir / "librdp-session-supervisor"
    )
    for path in (*applications, broker, agent, supervisor):
        executable(path)

    forbidden = (
        args.bindir / "librdp-session-broker",
        args.bindir / "librdp-session-agent",
        args.bindir / "librdp-session-supervisor",
        args.sbindir / "librdp-session-agent",
        args.sbindir / "librdp-session-supervisor",
    )
    for logical in forbidden:
        if staged_path(args.destdir, logical).exists():
            raise RuntimeError(
                f"managed-session helper installed in public command path: {logical}"
            )

    configured_agent = args.libexecdir / "librdp-session-agent"
    configured_supervisor = args.libexecdir / "librdp-session-supervisor"
    loader_path = staged_path(args.destdir, args.libdir)
    for variable in ("LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"):
        previous = environment.get(variable, "")
        environment[variable] = (
            f"{loader_path}{os.pathsep}{previous}"
            if previous
            else str(loader_path)
        )
    check_configured_paths(
        broker,
        environment,
        configured_supervisor,
        configured_agent,
    )

    config = staged_path(
        args.destdir, args.datadir / "librdp-session-broker.conf.example"
    ).read_text(encoding="utf-8")
    expected_lines = {
        "socket=/run/librdp/session-broker.sock",
        "runtime-root=/run/librdp/sessions",
        f"supervisor={configured_supervisor}",
        f"agent={configured_agent}",
        "auth-service=librdp",
    }
    actual_lines = set(config.splitlines())
    missing = sorted(expected_lines - actual_lines)
    if missing:
        raise RuntimeError(
            "installed broker configuration is missing: " + ", ".join(missing)
        )

    for section, name in (
        ("man1", "librdp-admin.1"),
        ("man1", "librdp-server.1"),
        ("man1", "librdp-viewer.1"),
        ("man1", "librdp-workspace.1"),
        ("man8", "librdp-session-broker.8"),
    ):
        manual = staged_path(args.destdir, args.mandir / section / name)
        if not manual.is_file():
            raise RuntimeError(f"installed manual page is missing: {manual}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.CalledProcessError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
