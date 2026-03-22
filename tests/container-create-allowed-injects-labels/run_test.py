from pathlib import Path
import sys

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from tests._shared.harness import (
    cleanup_container,
    create_container_via_proxy,
    ensure_image,
    inspect_container_labels,
    start_proxy,
    unique_name,
)


TEST_NAME = "container-create-allowed-injects-labels"


def main() -> None:
    test_dir = Path(__file__).resolve().parent
    ensure_image("alpine:latest")
    proxy = start_proxy(test_dir, TEST_NAME)
    container_name = unique_name("inject-labels")
    container_id = ""

    try:
        container_id = create_container_via_proxy(
            proxy.proxy_socket,
            {
                "Image": "alpine:latest",
                "Cmd": ["sleep", "30"],
                "Labels": {"existing": "value"},
            },
            name=container_name,
        )
        labels = inspect_container_labels(proxy.docker_host, container_id)
        if labels.get("ltkk.run/namespace") != "team-a":
            raise AssertionError(f"namespace label mismatch: {labels!r}")
        if labels.get("ltkk.run/managed-by") != "docker-hardened-proxy":
            raise AssertionError(f"managed-by label mismatch: {labels!r}")
        if labels.get("existing") != "value":
            raise AssertionError(f"existing label mismatch: {labels!r}")
        print(f"PASS: {TEST_NAME}")
    finally:
        if container_id:
            cleanup_container(proxy.docker_host, container_id)
        proxy.stop()


if __name__ == "__main__":
    main()
