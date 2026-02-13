"""Tests for agent profile endpoints."""

import base64
import requests
from nacl.signing import SigningKey


def _register_agent(base_url, platform="test", username=None):
    """Register a test agent and return (did, signing_key, public_key_b64)."""
    sk = SigningKey.generate()
    pk_b64 = base64.b64encode(sk.verify_key.encode()).decode()
    if username is None:
        username = f"test_{base64.b16encode(sk.encode()[:4]).decode().lower()}"
    import hashlib
    did = "did:aip:" + hashlib.sha256(sk.verify_key.encode()).hexdigest()[:32]
    resp = requests.post(f"{base_url}/register", json={
        "did": did,
        "platform": platform,
        "username": username,
        "public_key": pk_b64,
    })
    assert resp.status_code == 200, resp.text
    return did, sk, pk_b64


def _get_signed_challenge(base_url, did, sk):
    """Get a challenge and sign it."""
    resp = requests.post(f"{base_url}/challenge", json={"did": did})
    assert resp.status_code == 200
    challenge = resp.json()["challenge"]
    sig = base64.b64encode(sk.sign(challenge.encode()).signature).decode()
    return challenge, sig


def test_get_profile_empty(local_service):
    """Profile for a registered agent with no profile returns defaults."""
    did, sk, pk = _register_agent(local_service, username="profile_empty")
    resp = requests.get(f"{local_service}/agent/{did}/profile")
    assert resp.status_code == 200
    data = resp.json()
    assert data["did"] == did
    assert data["display_name"] is None
    assert data["tags"] == []


def test_get_profile_not_found(local_service):
    """Profile for non-existent DID returns 404."""
    resp = requests.get(f"{local_service}/agent/did:aip:nonexistent/profile")
    assert resp.status_code == 404


def test_update_profile(local_service):
    """Update profile with valid challenge-response auth."""
    did, sk, pk = _register_agent(local_service, username="profile_update")
    challenge, sig = _get_signed_challenge(local_service, did, sk)

    resp = requests.put(f"{local_service}/agent/{did}/profile", json={
        "did": did,
        "challenge": challenge,
        "signature": sig,
        "display_name": "Test Agent",
        "bio": "I am a test agent",
        "tags": ["test", "automated"],
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "updated"
    assert data["profile"]["display_name"] == "Test Agent"
    assert data["profile"]["bio"] == "I am a test agent"
    assert data["profile"]["tags"] == ["test", "automated"]

    # Verify GET returns updated profile
    resp2 = requests.get(f"{local_service}/agent/{did}/profile")
    assert resp2.status_code == 200
    assert resp2.json()["display_name"] == "Test Agent"


def test_update_profile_bad_signature(local_service):
    """Reject profile update with invalid signature."""
    did, sk, pk = _register_agent(local_service, username="profile_badsig")
    challenge, _ = _get_signed_challenge(local_service, did, sk)

    resp = requests.put(f"{local_service}/agent/{did}/profile", json={
        "did": did,
        "challenge": challenge,
        "signature": base64.b64encode(b"x" * 64).decode(),
        "display_name": "Hacked",
    })
    assert resp.status_code == 401


def test_update_profile_wrong_did(local_service):
    """Reject profile update when path DID doesn't match body DID."""
    did, sk, pk = _register_agent(local_service, username="profile_wrongdid")
    challenge, sig = _get_signed_challenge(local_service, did, sk)

    resp = requests.put(f"{local_service}/agent/did:aip:other/profile", json={
        "did": did,
        "challenge": challenge,
        "signature": sig,
        "display_name": "Test",
    })
    assert resp.status_code == 400


def test_update_profile_bio_too_long(local_service):
    """Reject bio over 500 chars."""
    did, sk, pk = _register_agent(local_service, username="profile_longbio")
    challenge, sig = _get_signed_challenge(local_service, did, sk)

    resp = requests.put(f"{local_service}/agent/{did}/profile", json={
        "did": did,
        "challenge": challenge,
        "signature": sig,
        "bio": "x" * 501,
    })
    assert resp.status_code in (400, 422)
