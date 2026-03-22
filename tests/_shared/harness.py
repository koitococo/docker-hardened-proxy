from __future__ import annotations

import os
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path


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
    body = body or b""
    headers = headers or {}
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(str(proxy_socket))
    try:
        request_lines = [
            f"{method} {path} HTTP/1.1",
            "Host: docker",
            f"Content-Length: {len(body)}",
        ]
        for key, value in headers.items():
            request_lines.append(f"{key}: {value}")
        raw = "\r\n".join(request_lines).encode("utf-8") + b"\r\n\r\n" + body
        sock.sendall(raw)

        response = bytearray()
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            response.extend(chunk)
    finally:
        sock.close()

    header_bytes, _, body_bytes = bytes(response).partition(b"\r\n\r\n")
    status_line = header_bytes.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
    status_code = int(status_line.split()[1])
    return status_code, body_bytes


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
