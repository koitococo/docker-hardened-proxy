from pathlib import Path
import sys

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from tests._shared.harness import (
    cleanup_container,
    create_container_via_proxy,
    docker_api_request,
    docker_cli,
    ensure_image,
    start_proxy,
    unique_name,
)


TEST_NAME = "namespace-cross-namespace-container-start-denied"


def main() -> None:
    test_dir = Path(__file__).resolve().parent
    ensure_image("alpine:latest")
    owner_proxy = start_proxy(
        test_dir.parents[0] / "container-create-allowed-injects-labels",
        "owner-proxy-start",
    )
    foreign_proxy = start_proxy(test_dir, TEST_NAME)
    container_id = ""
    try:
        container_id = create_container_via_proxy(
            owner_proxy.proxy_socket,
            {"Image": "alpine:latest", "Cmd": ["sleep", "30"]},
            name=unique_name("start-denied"),
        )
        status_code, body = docker_api_request(
            foreign_proxy.proxy_socket,
            "POST",
            f"/v1.52/containers/{container_id}/start",
        )
        if status_code != 403:
            raise AssertionError(
                f"expected status 403, got {status_code}, body={body!r}"
            )
        if b"does not belong to this namespace" not in body:
            raise AssertionError(f"unexpected body: {body!r}")
        inspect = docker_cli(
            owner_proxy.docker_host,
            "inspect",
            container_id,
            "--format",
            "{{.State.Running}}",
        )
        if inspect.stdout.strip() != "false":
            raise AssertionError(
                f"container should remain stopped, got {inspect.stdout!r}"
            )
        print(f"PASS: {TEST_NAME}")
    finally:
        if container_id:
            cleanup_container(owner_proxy.docker_host, container_id)
        foreign_proxy.stop()
        owner_proxy.stop()


if __name__ == "__main__":
    main()
