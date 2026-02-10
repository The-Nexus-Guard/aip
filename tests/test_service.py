#!/usr/bin/env python3
"""
AIP Service API Tests

Tests the FastAPI service endpoints.
Run with: python3 tests/test_service.py
"""

import sys
import os
from pathlib import Path

# Add paths
sys.path.insert(0, str(Path(__file__).parent.parent / "service"))
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

# Disable rate limiting for tests
os.environ["AIP_TESTING"] = "1"

# Set test database — use temp file so all connections share the same DB
import tempfile
_test_db_fd, _test_db_path = tempfile.mkstemp(suffix=".db")
os.close(_test_db_fd)
os.environ["AIP_DATABASE_PATH"] = _test_db_path

from fastapi.testclient import TestClient

_client = None

def get_test_client():
    """Get a test client (shared across tests, DB initialized once)."""
    global _client
    if _client is None:
        from main import app
        _client = TestClient(app)
        # Trigger startup event to init DB
        _client.__enter__()
    return _client


def teardown_module(module):
    """Cleanup test database."""
    global _client
    if _client is not None:
        _client.__exit__(None, None, None)
        _client = None
    if os.path.exists(_test_db_path):
        os.unlink(_test_db_path)


class TestHealthEndpoints:
    """Test health and info endpoints."""

    def test_root(self):
        """Root endpoint returns service info."""
        client = get_test_client()
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["service"] == "AIP - Agent Identity Protocol"
        assert "version" in data

    def test_stats(self):
        """Stats endpoint returns registration counts."""
        client = get_test_client()
        response = client.get("/stats")
        assert response.status_code == 200
        data = response.json()
        assert "stats" in data
        assert "registrations" in data["stats"]


class TestRegistration:
    """Test registration endpoints."""

    def test_easy_register(self):
        """Easy registration creates identity and returns keys."""
        client = get_test_client()
        response = client.post(
            "/register/easy",
            json={"platform": "moltbook", "username": "TestAgent"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["did"].startswith("did:aip:")
        assert "public_key" in data
        assert "private_key" in data
        assert data["platform"] == "moltbook"
        assert data["username"] == "TestAgent"

    def test_easy_register_duplicate_fails(self):
        """Cannot register same platform+username twice."""
        client = get_test_client()

        # First registration succeeds
        response1 = client.post(
            "/register/easy",
            json={"platform": "moltbook", "username": "DupeAgent"}
        )
        assert response1.status_code == 200

        # Second registration fails
        response2 = client.post(
            "/register/easy",
            json={"platform": "moltbook", "username": "DupeAgent"}
        )
        assert response2.status_code in (400, 409)

    def test_easy_register_missing_fields(self):
        """Registration requires platform and username."""
        client = get_test_client()

        response = client.post(
            "/register/easy",
            json={"platform": "moltbook"}  # Missing username
        )
        assert response.status_code == 422  # Validation error


class TestVerification:
    """Test verification endpoints."""

    def test_verify_registered_agent(self):
        """Can verify a registered agent."""
        client = get_test_client()

        # Register first
        reg_response = client.post(
            "/register/easy",
            json={"platform": "moltbook", "username": "VerifyMe"}
        )
        assert reg_response.status_code == 200
        did = reg_response.json()["did"]

        # Now verify
        verify_response = client.get(
            "/verify",
            params={"platform": "moltbook", "username": "VerifyMe"}
        )
        assert verify_response.status_code == 200
        data = verify_response.json()
        assert data["verified"] is True
        assert data["did"] == did

    def test_verify_unregistered_agent(self):
        """Verifying unregistered agent returns false."""
        client = get_test_client()

        response = client.get(
            "/verify",
            params={"platform": "moltbook", "username": "NotRegistered"}
        )
        # Unregistered agent returns 404 with verified=false message
        assert response.status_code in (200, 404)


class TestLookup:
    """Test lookup endpoints."""

    def test_lookup_by_did(self):
        """Can look up agent by DID."""
        client = get_test_client()

        # Register first
        reg_response = client.post(
            "/register/easy",
            json={"platform": "moltbook", "username": "LookupTest"}
        )
        did = reg_response.json()["did"]
        public_key = reg_response.json()["public_key"]

        # Lookup by DID
        lookup_response = client.get(f"/lookup/{did}")
        assert lookup_response.status_code == 200
        data = lookup_response.json()
        assert data["did"] == did
        assert data["public_key"] == public_key

    def test_lookup_unknown_did(self):
        """Looking up unknown DID returns 404."""
        client = get_test_client()

        response = client.get("/lookup/did:aip:nonexistent123456")
        assert response.status_code == 404


class TestChallenge:
    """Test challenge-response endpoints."""

    def test_create_challenge(self):
        """Can create a challenge."""
        client = get_test_client()

        # Register first to get a DID
        reg = client.post("/register/easy", json={"platform": "moltbook", "username": "ChallengeCreate"})
        assert reg.status_code == 200
        did = reg.json()["did"]

        response = client.post("/challenge", json={"did": did})
        assert response.status_code == 200
        data = response.json()
        assert "challenge" in data
        assert "expires_at" in data

    def test_respond_to_challenge(self):
        """Can respond to a challenge with valid signature."""
        client = get_test_client()
        import base64
        import nacl.signing

        # Register to get keys
        reg_response = client.post(
            "/register/easy",
            json={"platform": "moltbook", "username": "ChallengeTest"}
        )
        assert reg_response.status_code == 200
        did = reg_response.json()["did"]
        private_key_b64 = reg_response.json()["private_key"]

        # Create challenge
        challenge_response = client.post("/challenge", json={"did": did})
        assert challenge_response.status_code == 200
        challenge = challenge_response.json()["challenge"]

        # Sign the challenge string
        private_key_bytes = base64.b64decode(private_key_b64)
        signing_key = nacl.signing.SigningKey(private_key_bytes[:32])
        signed = signing_key.sign(challenge.encode('utf-8'))
        signature_b64 = base64.b64encode(signed.signature).decode()

        # Respond to challenge
        verify_response = client.post(
            "/verify-challenge",
            json={
                "did": did,
                "challenge": challenge,
                "signature": signature_b64
            }
        )
        assert verify_response.status_code == 200
        data = verify_response.json()
        assert data["verified"] is True


class TestSkillSigning:
    """Test skill signing endpoints."""

    def test_hash_content(self):
        """Hash endpoint returns valid SHA256 hash."""
        client = get_test_client()

        response = client.post(
            "/skill/hash",
            params={"skill_content": "# My Skill\n\nThis is a test skill."}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["content_hash"].startswith("sha256:")
        assert len(data["content_hash"]) == 71  # sha256: + 64 hex chars

    def test_verify_valid_signature(self):
        """Verify endpoint validates correct signatures."""
        client = get_test_client()
        import base64
        import nacl.signing

        # Register to get keys
        reg_response = client.post(
            "/register/easy",
            json={"platform": "moltbook", "username": "SkillSigner"}
        )
        assert reg_response.status_code == 200
        did = reg_response.json()["did"]
        private_key_b64 = reg_response.json()["private_key"]

        # Create content and hash
        content = "# Test Skill\n\nContent here."
        hash_response = client.post("/skill/hash", params={"skill_content": content})
        content_hash = hash_response.json()["content_hash"]

        # Create timestamp and payload
        from datetime import datetime, timezone
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        payload = f"{did}|{content_hash}|{timestamp}"

        # Sign payload
        private_key_bytes = base64.b64decode(private_key_b64)
        signing_key = nacl.signing.SigningKey(private_key_bytes[:32])
        signed = signing_key.sign(payload.encode('utf-8'))
        signature_b64 = base64.b64encode(signed.signature).decode()

        # Verify
        verify_response = client.get(
            "/skill/verify",
            params={
                "content_hash": content_hash,
                "author_did": did,
                "signature": signature_b64,
                "timestamp": timestamp
            }
        )
        assert verify_response.status_code == 200
        data = verify_response.json()
        assert data["verified"] is True
        assert data["author_did"] == did

    def test_verify_unregistered_author(self):
        """Verify fails for unregistered author DID."""
        client = get_test_client()

        response = client.get(
            "/skill/verify",
            params={
                "content_hash": "sha256:abc123",
                "author_did": "did:aip:nonexistent",
                "signature": "fake",
                "timestamp": "2026-02-05T00:00:00Z"
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["verified"] is False

    def test_verify_invalid_signature(self):
        """Verify fails for invalid signature."""
        client = get_test_client()
        import base64

        # Register first
        reg_response = client.post(
            "/register/easy",
            json={"platform": "moltbook", "username": "BadSigner"}
        )
        assert reg_response.status_code == 200
        did = reg_response.json()["did"]

        # Try to verify with bad signature
        bad_sig = base64.b64encode(b"x" * 64).decode()

        response = client.get(
            "/skill/verify",
            params={
                "content_hash": "sha256:abc123",
                "author_did": did,
                "signature": bad_sig,
                "timestamp": "2026-02-05T00:00:00Z"
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["verified"] is False


class TestVouchCertificateForgery:
    """Test that forged vouch certificates are rejected."""

    def test_forged_certificate_rejected(self):
        """A certificate with a substituted public key must be rejected."""
        client = get_test_client()
        import base64

        # Register voucher and target (unique names to avoid collisions)
        import uuid
        r1 = client.post("/register/easy", json={"platform": "test", "username": f"voucher_{uuid.uuid4().hex[:8]}"})
        assert r1.status_code == 200, f"Registration failed: {r1.json()}"
        voucher_did = r1.json()["did"]

        r2 = client.post("/register/easy", json={"platform": "test", "username": f"target_{uuid.uuid4().hex[:8]}"})
        assert r2.status_code == 200, f"Registration failed: {r2.json()}"
        target_did = r2.json()["did"]

        # Generate attacker keypair and forge a certificate
        try:
            from pure25519 import eddsa as ed
            from pure25519.basic import bytes_to_clamped, Base
            import hashlib
            # Generate a random attacker keypair
            import secrets
            seed = secrets.token_bytes(32)
            # Use pure25519 to create a signing key
            _, vk_bytes = ed.create_keypair(seed)
            attacker_public = base64.b64encode(vk_bytes).decode()
            # Sign a payload with attacker key
            payload = f"{voucher_did}|{target_did}|GENERAL|forged"
            sig = ed.sign(seed, payload.encode('utf-8'))
            attacker_sig = base64.b64encode(sig).decode()
        except (ImportError, Exception):
            import nacl.signing
            attacker_key = nacl.signing.SigningKey.generate()
            attacker_public = base64.b64encode(attacker_key.verify_key.encode()).decode()
            payload = f"{voucher_did}|{target_did}|GENERAL|forged"
            signed = attacker_key.sign(payload.encode('utf-8'))
            attacker_sig = base64.b64encode(signed.signature).decode()

        # Submit forged certificate — signature is valid for attacker's key,
        # but the key doesn't match voucher_did's registered key
        from datetime import datetime
        cert = {
            "version": "1.0",
            "vouch_id": "fake-vouch-id",
            "voucher_did": voucher_did,
            "voucher_public_key": attacker_public,
            "target_did": target_did,
            "scope": "GENERAL",
            "statement": "forged",
            "created_at": datetime.utcnow().isoformat(),
            "expires_at": None,
            "signature": attacker_sig,
            "certificate_issued_at": datetime.utcnow().isoformat()
        }

        response = client.post("/vouch/verify-certificate", json=cert)
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is False
        assert "does not match registered key" in data["reason"]


def run_tests():
    """Run all tests manually."""
    import traceback

    test_classes = [
        TestHealthEndpoints,
        TestRegistration,
        TestVerification,
        TestLookup,
        TestChallenge,
        TestSkillSigning,
        TestVouchCertificateForgery
    ]
    passed = 0
    failed = 0

    print("AIP Service API Tests")
    print("=" * 60)

    for test_class in test_classes:
        print(f"\n{test_class.__name__}:")
        instance = test_class()

        for name in dir(instance):
            if name.startswith("test_"):
                try:
                    getattr(instance, name)()
                    print(f"  ✓ {name}")
                    passed += 1
                except Exception as e:
                    print(f"  ✗ {name}: {e}")
                    traceback.print_exc()
                    failed += 1

    print("\n" + "=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    return failed == 0


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
