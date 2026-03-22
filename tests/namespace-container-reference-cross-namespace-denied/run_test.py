from pathlib import Path
import sys

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from tests._shared.harness import (
    cleanup_container,
    create_container_via_proxy,
    docker_api_json,
    ensure_image,
    start_proxy,
    unique_name,
)


TEST_NAME = "namespace-container-reference-cross-namespace-denied"


def main() -> None:
    test_dir = Path(__file__).resolve().parent
    ensure_image("alpine:latest")
    owner_proxy = start_proxy(
        test_dir.parents[0] / "container-create-allowed-injects-labels", "owner-proxy"
    )
    foreign_proxy = start_proxy(test_dir, TEST_NAME)
    base_container_id = ""

    try:
        base_container_id = create_container_via_proxy(
            owner_proxy.proxy_socket,
            {"Image": "alpine:latest", "Cmd": ["sleep", "30"]},
            name=unique_name("team-a-base"),
        )
        status_code, body = docker_api_json(
            foreign_proxy.proxy_socket,
            "POST",
            f"/v1.52/containers/create?name={unique_name('foreign-ref')}",
            {
                "Image": "alpine:latest",
                "Cmd": ["true"],
                "HostConfig": {"NetworkMode": f"container:{base_container_id}"},
            },
        )
        if status_code != 403:
            raise AssertionError(
                f"expected status 403, got {status_code}, body={body!r}"
            )
        if b"outside this namespace" not in body:
            raise AssertionError(f"unexpected body: {body!r}")
        print(f"PASS: {TEST_NAME}")
    finally:
        if base_container_id:
            cleanup_container(owner_proxy.docker_host, base_container_id)
        foreign_proxy.stop()
        owner_proxy.stop()


if __name__ == "__main__":
    main()
