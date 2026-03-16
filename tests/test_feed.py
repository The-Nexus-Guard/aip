"""Tests for /feed trust event endpoint."""

import sys
import os
import tempfile
from pathlib import Path

# Add service path
sys.path.insert(0, str(Path(__file__).parent.parent / "service"))

# Disable rate limiting
os.environ["AIP_TESTING"] = "1"

# Use temp file DB
_test_db_fd, _test_db_path = tempfile.mkstemp(suffix=".db")
os.close(_test_db_fd)
os.environ["AIP_DATABASE_PATH"] = _test_db_path

from fastapi.testclient import TestClient
from main import app
from database import init_database

init_database()
_client = TestClient(app)
_client.__enter__()


def test_feed_empty():
    """Empty feed returns valid structure."""
    resp = _client.get("/feed")
    assert resp.status_code == 200
    data = resp.json()
    assert "events" in data
    assert "count" in data
    assert data["count"] >= 0


def test_feed_after_registration():
    """Feed includes registration events."""
    import nacl.signing
    import base64
    import hashlib

    sk = nacl.signing.SigningKey.generate()
    pub = base64.b64encode(bytes(sk.verify_key)).decode()
    did = "did:aip:" + hashlib.sha256(bytes(sk.verify_key)).hexdigest()[:32]

    resp = _client.post("/register", json={
        "did": did,
        "public_key": pub,
        "platform": "test",
        "username": "feed_test_agent",
    })
    assert resp.status_code == 200

    # Check feed
    resp = _client.get("/feed")
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] >= 1
    reg_events = [e for e in data["events"] if e["type"] == "registration"]
    assert len(reg_events) >= 1
    assert any(e["did"] == did for e in reg_events)


def test_feed_type_filter():
    """Type filter returns only matching events."""
    resp = _client.get("/feed?type=vouch")
    assert resp.status_code == 200
    data = resp.json()
    for e in data["events"]:
        assert e["type"] == "vouch"


def test_feed_atom_format():
    """Atom format returns valid XML."""
    resp = _client.get("/feed?format=atom")
    assert resp.status_code == 200
    assert "application/atom+xml" in resp.headers["content-type"]
    assert "<?xml" in resp.text
    assert "<feed" in resp.text
    assert "AIP Trust Network Feed" in resp.text


def test_feed_limit():
    """Limit parameter is respected."""
    resp = _client.get("/feed?limit=5")
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] <= 5


def test_feed_since_filter():
    """Since parameter filters old events."""
    resp = _client.get("/feed?since=2099-01-01T00:00:00")
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] == 0
