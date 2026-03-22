from pathlib import Path
import sys

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from tests._shared.harness import (
    docker_buildx_cli,
    start_proxy,
)


TEST_NAME = "buildkit-control-disk-usage-denied-by-default"


def main() -> None:
    test_dir = Path(__file__).resolve().parent
    proxy = start_proxy(test_dir, TEST_NAME)
    try:
        result = docker_buildx_cli(proxy.docker_host, "du", check=False)
        combined = (result.stdout + result.stderr).encode("utf-8", errors="replace")
        if result.returncode == 0:
            raise AssertionError(f"expected non-zero exit, got success: {combined!r}")
        if (
            b"DiskUsage" not in combined
            and b"denied by policy" not in combined
            and b"Unavailable" not in combined
            and b"connection reset by peer" not in combined
            and b"rpc error" not in combined
        ):
            raise AssertionError(f"unexpected output: {combined!r}")
        print(f"PASS: {TEST_NAME}")
    finally:
        proxy.stop()


if __name__ == "__main__":
    main()
