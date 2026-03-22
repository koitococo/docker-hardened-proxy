from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from tests._shared import harness


class BinaryRebuildTests(unittest.TestCase):
    def test_binary_needs_rebuild_when_source_is_newer(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            binary_path = temp_path / "docker-hardened-proxy"
            source_path = temp_path / "internal" / "proxy" / "proxy.go"
            source_path.parent.mkdir(parents=True, exist_ok=True)

            binary_path.write_bytes(b"binary")
            source_path.write_text("package proxy\n", encoding="utf-8")

            os.utime(binary_path, (100, 100))
            os.utime(source_path, (200, 200))

            self.assertTrue(harness.binary_needs_rebuild(binary_path, [source_path]))

    def test_binary_does_not_rebuild_when_binary_is_newest(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            binary_path = temp_path / "docker-hardened-proxy"
            source_path = temp_path / "go.mod"

            binary_path.write_bytes(b"binary")
            source_path.write_text("module example\n", encoding="utf-8")

            os.utime(source_path, (100, 100))
            os.utime(binary_path, (200, 200))

            self.assertFalse(harness.binary_needs_rebuild(binary_path, [source_path]))

    def test_binary_needs_rebuild_when_binary_missing(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            binary_path = temp_path / "docker-hardened-proxy"
            source_path = temp_path / "cmd" / "docker-hardened-proxy" / "main.go"
            source_path.parent.mkdir(parents=True, exist_ok=True)
            source_path.write_text("package main\n", encoding="utf-8")

            self.assertTrue(harness.binary_needs_rebuild(binary_path, [source_path]))


if __name__ == "__main__":
    unittest.main()
