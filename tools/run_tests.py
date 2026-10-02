#!/usr/bin/env python3
"""Deterministic local test entrypoint (W0-002 exit)."""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    return subprocess.call([sys.executable, "-m", "pytest", "-q", str(ROOT / "tests")], cwd=ROOT)


if __name__ == "__main__":
    raise SystemExit(main())
