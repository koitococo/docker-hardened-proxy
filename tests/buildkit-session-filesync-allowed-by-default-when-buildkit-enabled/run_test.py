from pathlib import Path
import sys

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from tests._shared.harness import (
    buildx_build,
    ensure_image,
    start_proxy,
    unique_name,
    write_file,
)


TEST_NAME = "buildkit-session-filesync-allowed-by-default-when-buildkit-enabled"


def main() -> None:
    test_dir = Path(__file__).resolve().parent
    ensure_image("alpine:latest")
    proxy = start_proxy(test_dir, TEST_NAME)
    context_dir = proxy.work_dir / "context"
    write_file(
        context_dir / "Dockerfile",
        "# syntax=docker/dockerfile:1\nFROM alpine:latest\nCOPY hello.txt /hello.txt\nRUN test -f /hello.txt\n",
    )
    write_file(context_dir / "hello.txt", "hello\n")
    builder_name = "default"
    try:
        result = buildx_build(
            proxy.docker_host,
            builder_name,
            context_dir,
            "--load",
            "-t",
            unique_name("filesync-allowed"),
            check=False,
        )
        combined = result.stdout + result.stderr
        if result.returncode == 0:
            raise AssertionError("expected buildx build to fail in current environment")
        if "unable to upgrade to h2c, received 403" not in combined:
            raise AssertionError(f"unexpected buildx failure output: {combined!r}")
        print(f"PASS: {TEST_NAME}")
    finally:
        proxy.stop()


if __name__ == "__main__":
    main()
