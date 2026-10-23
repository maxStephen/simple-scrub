#!/usr/bin/env python3
"""Run every test script. Usage: .venv/bin/python tests/run_all.py

Needs requirements.txt and requirements-dev.txt installed, plus the tesseract binary.
"""

import subprocess
import sys
from pathlib import Path

here = Path(__file__).resolve().parent
scripts = sorted(here.glob("test_*.py"))
failed = []
for script in scripts:
    print(f"\n=== {script.name}")
    if subprocess.run([sys.executable, str(script)]).returncode:
        failed.append(script.name)

print("\n" + ("ALL PASSED" if not failed else f"FAILED: {', '.join(failed)}"))
sys.exit(1 if failed else 0)
