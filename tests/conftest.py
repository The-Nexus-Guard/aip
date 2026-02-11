"""Shared fixtures for AIP tests."""

import os
import sys
import socket
import tempfile
import threading
import time

import pytest
import requests
import uvicorn

# Ensure service package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "service"))


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def local_service():
    """Start a local AIP service on a random port with a temp database."""
    port = _free_port()
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(db_fd)

    # Set env before importing the app
    os.environ["AIP_DATABASE_PATH"] = db_path
    os.environ["AIP_TESTING"] = "1"

    # Import app inside fixture so env is set first
    from main import app  # service/main.py

    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)

    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    base_url = f"http://127.0.0.1:{port}"

    # Wait for server to be ready
    for _ in range(50):
        try:
            r = requests.get(f"{base_url}/", timeout=1)
            if r.status_code == 200:
                break
        except requests.ConnectionError:
            pass
        time.sleep(0.1)
    else:
        raise RuntimeError("Local AIP service did not start in time")

    yield base_url

    server.should_exit = True
    thread.join(timeout=5)
    try:
        os.unlink(db_path)
    except OSError:
        pass
