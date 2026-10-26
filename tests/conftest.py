from __future__ import annotations

import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1]
SAMPLE_API = ROOT / "tests" / "fixtures" / "sample_api"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def sample_api_dir() -> Path:
    return SAMPLE_API


@pytest.fixture(scope="session")
def sample_server():
    """Run the bundled FastAPI sample on a free local port for integration tests."""
    port = free_port()
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--app-dir", str(SAMPLE_API), "--port", str(port), "--log-level", "warning"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    url = f"http://127.0.0.1:{port}"
    try:
        for _ in range(60):
            try:
                if httpx.get(url + "/health", timeout=1).status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(0.25)
        else:
            raise RuntimeError("sample server did not start")
        yield url
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


def write_files(root: Path, files: dict[str, str]) -> Path:
    for rel_path, content in files.items():
        p = root / rel_path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return root
