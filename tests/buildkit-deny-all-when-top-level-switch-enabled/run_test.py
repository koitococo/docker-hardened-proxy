from pathlib import Path
import sys

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from tests._shared.harness import docker_api_request, start_proxy


TEST_NAME = "buildkit-deny-all-when-top-level-switch-enabled"


def main() -> None:
    test_dir = Path(__file__).resolve().parent
    proxy = start_proxy(test_dir, TEST_NAME)
    try:
        status_code, body = docker_api_request(
            proxy.proxy_socket,
            "POST",
            "/session",
            headers={
                "Connection": "Upgrade, HTTP2-Settings",
                "Upgrade": "h2c",
                "HTTP2-Settings": "AAMAAABkAAQAAP__",
            },
        )
        if status_code != 403:
            raise AssertionError(
                f"expected status 403, got {status_code}, body={body!r}"
            )
        if b"buildkit is disabled by policy" not in body:
            raise AssertionError(f"unexpected body: {body!r}")
        print(f"PASS: {TEST_NAME}")
    finally:
        proxy.stop()


if __name__ == "__main__":
    main()
