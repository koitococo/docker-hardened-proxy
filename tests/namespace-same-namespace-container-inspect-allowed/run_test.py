from pathlib import Path
import sys

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from tests._shared.harness import (
    cleanup_container,
    create_container_via_proxy,
    docker_api_request,
    ensure_image,
    start_proxy,
    unique_name,
)


TEST_NAME = "namespace-same-namespace-container-inspect-allowed"


def main() -> None:
    test_dir = Path(__file__).resolve().parent
    ensure_image("alpine:latest")
    proxy = start_proxy(test_dir, TEST_NAME)
    container_id = ""
    try:
        container_id = create_container_via_proxy(
            proxy.proxy_socket,
            {"Image": "alpine:latest", "Cmd": ["sleep", "30"]},
            name=unique_name("same-namespace"),
        )
        status_code, body = docker_api_request(
            proxy.proxy_socket,
            "GET",
            f"/v1.52/containers/{container_id}/json",
        )
        if status_code != 200:
            raise AssertionError(
                f"expected status 200, got {status_code}, body={body!r}"
            )
        if container_id.encode("utf-8") not in body:
            raise AssertionError(f"expected container id in inspect body: {body!r}")
        print(f"PASS: {TEST_NAME}")
    finally:
        if container_id:
            cleanup_container(proxy.docker_host, container_id)
        proxy.stop()


if __name__ == "__main__":
    main()
