#!/usr/bin/env python3
# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Run Doxygen over the public headers with warnings promoted to errors."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    doxygen = shutil.which("doxygen")
    if doxygen is None:
        print("error: doxygen executable not found", file=sys.stderr)
        return 1
    result = subprocess.run(
        [doxygen, "Doxyfile"],
        cwd=ROOT,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if result.stdout:
        print(result.stdout, end="")
    if result.returncode != 0:
        print("error: Doxygen public header validation failed", file=sys.stderr)
        return result.returncode
    print("Doxygen public header guardrail passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
