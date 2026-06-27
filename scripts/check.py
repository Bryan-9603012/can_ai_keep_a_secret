from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import shutil
import os
from typing import Optional


def find_powershell() -> Optional[str]:
    candidates = [
        "powershell.exe",
        "pwsh.exe",
        "powershell",
        "pwsh",
    ]

    for name in candidates:
        path = shutil.which(name)
        if path:
            return path

    return None


def translate_args(args: list[str]) -> list[str]:
    """
    Convert simple Python-style arguments into PowerShell parameters.

    Examples:
      python3 check.py --env-only
      python3 check.py --skip-report
      python3 check.py --distro Ubuntu-22.04
      python3 check.py --timeout 120
    """

    result = []
    i = 0

    while i < len(args):
        arg = args[i]

        if arg == "--env-only":
            result.append("-EnvOnly")

        elif arg == "--skip-benchmark":
            result.append("-SkipBenchmark")

        elif arg == "--skip-report":
            result.append("-SkipReport")

        elif arg == "--distro":
            if i + 1 >= len(args):
                raise ValueError("--distro requires a value, for example: --distro Ubuntu-22.04")
            result.extend(["-DistroName", args[i + 1]])
            i += 1

        elif arg == "--timeout":
            if i + 1 >= len(args):
                raise ValueError("--timeout requires a value, for example: --timeout 120")
            result.extend(["-TimeoutSec", args[i + 1]])
            i += 1

        else:
            # Pass unknown args directly to PowerShell.
            result.append(arg)

        i += 1

    return result


def main() -> int:
    if os.name != "nt":
        print("[FAIL] This launcher is designed for Windows PowerShell.")
        return 1

    root = Path(__file__).resolve().parent
    ps1_path = root / "run_local_test.ps1"

    if not ps1_path.exists():
        print(f"[FAIL] Cannot find: {ps1_path}")
        print("Please put check.py in the same folder as run_local_test.ps1.")
        return 1

    powershell = find_powershell()

    if powershell is None:
        print("[FAIL] Cannot find PowerShell.")
        return 1

    try:
        ps_args = translate_args(sys.argv[1:])
    except ValueError as exc:
        print(f"[FAIL] {exc}")
        return 1

    cmd = [
        powershell,
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(ps1_path),
        *ps_args,
    ]

    print("[INFO] Running local test wizard...")
    print("[INFO] Command:")
    print(" ".join(f'"{x}"' if " " in x else x for x in cmd))
    print()

    return subprocess.call(cmd, cwd=root)


if __name__ == "__main__":
    raise SystemExit(main())