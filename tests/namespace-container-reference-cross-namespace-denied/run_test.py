from pathlib import Path
import sys

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from tests._shared.harness import require_docker_host


TEST_NAME = "namespace-container-reference-cross-namespace-denied"


def main() -> None:
    require_docker_host()
    test_dir = Path(__file__).resolve().parent
    print(f"placeholder: {TEST_NAME} @ {test_dir}")
    print("Arrange / Act / Assert will be implemented in the next step.")


if __name__ == "__main__":
    main()
