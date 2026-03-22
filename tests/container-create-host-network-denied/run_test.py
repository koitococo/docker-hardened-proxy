from pathlib import Path
import sys

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from tests._shared.harness import (
    docker_api_json,
    ensure_image,
    start_proxy,
    unique_name,
)


TEST_NAME = "container-create-host-network-denied"


def main() -> None:
    test_dir = Path(__file__).resolve().parent
    ensure_image("alpine:latest")
    proxy = start_proxy(test_dir, TEST_NAME)
    try:
        status_code, body = docker_api_json(
            proxy.proxy_socket,
            "POST",
            f"/v1.52/containers/create?name={unique_name('host-network-denied')}",
            {
                "Image": "alpine:latest",
                "Cmd": ["true"],
                "HostConfig": {"NetworkMode": "host"},
            },
        )
        if status_code != 403:
            raise AssertionError(
                f"expected status 403, got {status_code}, body={body!r}"
            )
        if b'NetworkMode="host" is denied' not in body:
            raise AssertionError(f"unexpected body: {body!r}")
        print(f"PASS: {TEST_NAME}")
    finally:
        proxy.stop()


if __name__ == "__main__":
    main()
