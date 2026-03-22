from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent


def discover_tests() -> list[Path]:
    result = []
    for path in sorted(ROOT_DIR.iterdir()):
        if not path.is_dir():
            continue
        if path.name.startswith("_") or path.name.startswith("."):
            continue
        script = path / "run_test.py"
        if script.exists():
            result.append(script)
    return result


def run_test(script: Path) -> tuple[bool, str]:
    proc = subprocess.run(
        [sys.executable, str(script)],
        cwd=ROOT_DIR,
        text=True,
        capture_output=True,
    )
    output = (proc.stdout + proc.stderr).strip()
    return proc.returncode == 0, output


def main() -> None:
    scripts = discover_tests()
    if not scripts:
        raise SystemExit("no test scripts found")

    failures: list[tuple[str, str]] = []
    for script in scripts:
        ok, output = run_test(script)
        name = script.parent.name
        if ok:
            print(f"PASS {name}")
            continue
        print(f"FAIL {name}")
        failures.append((name, output))

    print(f"\nSummary: {len(scripts) - len(failures)}/{len(scripts)} passed")
    if failures:
        print("\nFailures:")
        for name, output in failures:
            print(f"--- {name} ---")
            print(output)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
