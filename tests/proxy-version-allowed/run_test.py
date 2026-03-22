from pathlib import Path
import json
import sys

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from tests._shared.harness import docker_api_request, start_proxy


TEST_NAME = "proxy-version-allowed"


def main() -> None:
    test_dir = Path(__file__).resolve().parent
    proxy = start_proxy(test_dir, TEST_NAME)
    try:
        status_code, body = docker_api_request(proxy.proxy_socket, "GET", "/version")
        if status_code != 200:
            raise AssertionError(
                f"expected status 200, got {status_code}, body={body!r}"
            )
        payload = json.loads(body.decode("utf-8"))
        if "Version" not in payload or "ApiVersion" not in payload:
            raise AssertionError(f"missing expected version keys: {payload!r}")
        print(f"PASS: {TEST_NAME}")
    finally:
        proxy.stop()


if __name__ == "__main__":
    main()
