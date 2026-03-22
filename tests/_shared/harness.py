from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
import urllib.parse
import uuid
from pathlib import Path

import requests_unixsocket
import json
import tarfile


ROOT_DIR = Path(__file__).resolve().parents[2]
TESTS_DIR = ROOT_DIR / "tests"
BUILD_DIR = TESTS_DIR / ".build"
BIN_PATH = BUILD_DIR / "docker-hardened-proxy"


def require_docker_host() -> str:
    docker_host = os.environ.get("DOCKER_HOST", "").strip()
    if not docker_host:
        raise RuntimeError("DOCKER_HOST is required")
    return docker_host


def ensure_binary() -> Path:
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    if BIN_PATH.exists():
        return BIN_PATH

    subprocess.run(
        [
            "go",
            "build",
            "-o",
            str(BIN_PATH),
            "./cmd/docker-hardened-proxy",
        ],
        cwd=ROOT_DIR,
        check=True,
    )
    return BIN_PATH


def proxy_docker_host(proxy_socket: Path) -> str:
    return f"unix://{proxy_socket}"


def load_config_template(test_dir: Path) -> str:
    return (test_dir / "config.yaml").read_text(encoding="utf-8")


def make_work_dir(test_name: str) -> Path:
    return Path(tempfile.mkdtemp(prefix=f"dhp-{test_name}-"))


def render_config(template: str, docker_host: str, proxy_socket: Path) -> str:
    return template.replace("__DOCKER_HOST__", docker_host).replace(
        "__PROXY_SOCKET__", str(proxy_socket)
    )


def write_runtime_config(work_dir: Path, rendered: str) -> Path:
    path = work_dir / "config.yaml"
    path.write_text(rendered, encoding="utf-8")
    return path


def wait_for_unix_socket(socket_path: Path, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if socket_path.exists():
            return
        time.sleep(0.05)
    raise TimeoutError(f"proxy socket not ready: {socket_path}")


def docker_api_request(
    proxy_socket: Path,
    method: str,
    path: str,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, bytes]:
    encoded_socket = urllib.parse.quote(str(proxy_socket), safe="")
    url = f"http+unix://{encoded_socket}{path}"
    session = requests_unixsocket.Session()
    response = session.request(
        method=method,
        url=url,
        data=body,
        headers=headers,
        timeout=10,
    )
    return response.status_code, response.content


def docker_api_json(
    proxy_socket: Path,
    method: str,
    path: str,
    payload: dict | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, bytes]:
    encoded = json.dumps(payload).encode("utf-8") if payload is not None else None
    request_headers = {"Content-Type": "application/json"}
    if headers:
        request_headers.update(headers)
    return docker_api_request(
        proxy_socket=proxy_socket,
        method=method,
        path=path,
        body=encoded,
        headers=request_headers,
    )


def docker_cli(
    host: str, *args: str, check: bool = True
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["DOCKER_HOST"] = host
    docker_config = TESTS_DIR / ".docker-config"
    docker_config.mkdir(parents=True, exist_ok=True)
    env["DOCKER_CONFIG"] = str(docker_config)
    return subprocess.run(
        ["docker", *args],
        cwd=ROOT_DIR,
        env=env,
        check=check,
        text=True,
        capture_output=True,
    )


def ensure_image(image: str) -> None:
    upstream = require_docker_host()
    inspect_result = docker_cli(upstream, "image", "inspect", image, check=False)
    if inspect_result.returncode == 0:
        return
    archive_path = TESTS_DIR / ".empty-image.tar"
    if not archive_path.exists():
        with tarfile.open(archive_path, mode="w"):
            pass
    docker_cli(upstream, "import", str(archive_path), image)


def unique_name(prefix: str) -> str:
    suffix = uuid.uuid4().hex[:8]
    return f"{prefix}-{suffix}"


def cleanup_container(host: str, name_or_id: str) -> None:
    docker_cli(host, "rm", "-f", name_or_id, check=False)


def inspect_container_labels(host: str, container_id: str) -> dict[str, str]:
    result = docker_cli(
        host, "inspect", container_id, "--format", "{{json .Config.Labels}}"
    )
    labels = json.loads(result.stdout.strip())
    return labels or {}


def create_container_via_proxy(proxy_socket: Path, payload: dict, *, name: str) -> str:
    status_code, body = docker_api_json(
        proxy_socket,
        "POST",
        f"/v1.52/containers/create?name={urllib.parse.quote(name, safe='')}",
        payload,
    )
    if status_code != 201:
        raise AssertionError(
            f"expected create status 201, got {status_code}, body={body!r}"
        )
    response = json.loads(body.decode("utf-8"))
    return response["Id"]


class ProxyProcess:
    def __init__(
        self, process: subprocess.Popen[bytes], work_dir: Path, proxy_socket: Path
    ):
        self.process = process
        self.work_dir = work_dir
        self.proxy_socket = proxy_socket

    def stop(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        shutil.rmtree(self.work_dir, ignore_errors=True)

    @property
    def docker_host(self) -> str:
        return proxy_docker_host(self.proxy_socket)


def start_proxy(test_dir: Path, test_name: str) -> ProxyProcess:
    docker_host = require_docker_host()
    binary = ensure_binary()
    work_dir = make_work_dir(test_name)
    proxy_socket = work_dir / "proxy.sock"
    rendered = render_config(load_config_template(test_dir), docker_host, proxy_socket)
    config_path = write_runtime_config(work_dir, rendered)

    log_path = work_dir / "proxy.log"
    log_file = log_path.open("wb")
    process = subprocess.Popen(
        [str(binary), "-config", str(config_path)],
        cwd=ROOT_DIR,
        stdout=log_file,
        stderr=subprocess.STDOUT,
    )

    try:
        wait_for_unix_socket(proxy_socket)
    except Exception:
        process.terminate()
        process.wait(timeout=5)
        log_file.close()
        raise

    log_file.close()
    return ProxyProcess(process=process, work_dir=work_dir, proxy_socket=proxy_socket)
