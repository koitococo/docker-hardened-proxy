from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent
REPORTS_DIR = ROOT_DIR / "reports"


@dataclass
class TestResult:
    name: str
    ok: bool
    returncode: int
    duration_seconds: float
    stdout: str
    stderr: str


def discover_tests(pattern: str | None = None) -> list[Path]:
    result: list[Path] = []
    for path in sorted(ROOT_DIR.iterdir()):
        if not path.is_dir():
            continue
        if (
            path.name.startswith("_")
            or path.name.startswith(".")
            or path.name == "reports"
        ):
            continue
        if pattern and pattern not in path.name:
            continue
        script = path / "run_test.py"
        if script.exists():
            result.append(script)
    return result


def run_test(script: Path) -> TestResult:
    started = time.perf_counter()
    proc = subprocess.run(
        [sys.executable, str(script)],
        cwd=ROOT_DIR,
        text=True,
        capture_output=True,
        env=os.environ.copy(),
    )
    duration = time.perf_counter() - started
    return TestResult(
        name=script.parent.name,
        ok=proc.returncode == 0,
        returncode=proc.returncode,
        duration_seconds=duration,
        stdout=proc.stdout,
        stderr=proc.stderr,
    )


def format_text_report(results: list[TestResult], total_duration: float) -> str:
    passed = sum(1 for item in results if item.ok)
    failed = len(results) - passed
    lines = [
        "# Integration Test Report",
        "",
        f"Generated: {datetime.now(UTC).isoformat()}",
        f"Total: {len(results)}",
        f"Passed: {passed}",
        f"Failed: {failed}",
        f"Duration: {total_duration:.2f}s",
        "",
        "## Results",
    ]
    for item in results:
        status = "PASS" if item.ok else "FAIL"
        lines.append(f"- {status} {item.name} ({item.duration_seconds:.2f}s)")

    failures = [item for item in results if not item.ok]
    if failures:
        lines.extend(["", "## Failures"])
        for item in failures:
            lines.append(f"### {item.name}")
            lines.append("")
            if item.stdout.strip():
                lines.append("#### stdout")
                lines.append("```text")
                lines.append(item.stdout.rstrip())
                lines.append("```")
            if item.stderr.strip():
                lines.append("#### stderr")
                lines.append("```text")
                lines.append(item.stderr.rstrip())
                lines.append("```")
    return "\n".join(lines) + "\n"


def write_reports(
    results: list[TestResult], total_duration: float
) -> tuple[Path, Path]:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    json_path = REPORTS_DIR / "latest.json"
    text_path = REPORTS_DIR / "latest.txt"

    payload = {
        "generated_at": datetime.now(UTC).isoformat(),
        "total": len(results),
        "passed": sum(1 for item in results if item.ok),
        "failed": sum(1 for item in results if not item.ok),
        "duration_seconds": total_duration,
        "results": [asdict(item) for item in results],
    }
    json_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    text_path.write_text(format_text_report(results, total_duration), encoding="utf-8")
    return json_path, text_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Run integration tests in parallel")
    parser.add_argument("--workers", type=int, default=min(4, os.cpu_count() or 1))
    parser.add_argument("--pattern", type=str, default=None)
    args = parser.parse_args()

    scripts = discover_tests(args.pattern)
    if not scripts:
        raise SystemExit("no test scripts found")

    started = time.perf_counter()
    results: list[TestResult] = []
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        future_map = {executor.submit(run_test, script): script for script in scripts}
        for future in as_completed(future_map):
            result = future.result()
            results.append(result)
            status = "PASS" if result.ok else "FAIL"
            print(f"{status} {result.name} ({result.duration_seconds:.2f}s)")

    results.sort(key=lambda item: item.name)
    total_duration = time.perf_counter() - started
    json_path, text_path = write_reports(results, total_duration)

    passed = sum(1 for item in results if item.ok)
    failed = len(results) - passed
    print(f"\nSummary: {passed}/{len(results)} passed in {total_duration:.2f}s")
    print(f"JSON report: {json_path}")
    print(f"Text report: {text_path}")

    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
