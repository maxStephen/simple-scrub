"""Shared helpers for the scripts in tests/. Fake data only."""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRUB = ROOT / "scrub.py"
sys.path.insert(0, str(ROOT))


def run(*args) -> subprocess.CompletedProcess:
    """Run scrub.py as a subprocess and return the result (text mode)."""
    return subprocess.run(
        [sys.executable, str(SCRUB), *map(str, args)], capture_output=True, text=True
    )


class Checker:
    def __init__(self, name: str):
        self.name = name
        self.failures = 0
        self.passed = 0

    def check(self, condition: bool, label: str, detail: str = "") -> None:
        if condition:
            self.passed += 1
            print(f"  ok    {label}")
        else:
            self.failures += 1
            print(f"  FAIL  {label}" + (f"\n        {detail.strip()[:300]}" if detail else ""))

    def finish(self) -> None:
        print(f"{self.name}: {self.passed} passed, {self.failures} failed")
        sys.exit(1 if self.failures else 0)
