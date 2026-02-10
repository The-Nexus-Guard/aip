#!/usr/bin/env python3
"""
AIP Service API Tests

Tests the FastAPI service endpoints.
Run with: python3 tests/test_service.py
"""

import sys
import os
import uuid
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


class TestMessageReplayProtection:
    """Test message replay vulnerability fix [MED-7]."""

    def _register_agent(self, name):
        """Register an agent via /register/easy and return (did, signing_key)."""
        import base64
        import nacl.signing
        client = get_test_client()
        resp = client.post("/register/easy", json={
            "platform": "test",
            "username": f"replay_{name}_{uuid.uuid4().hex[:6]}"
        })
        assert resp.status_code == 200, f"Registration failed: {resp.text}"
        data = resp.json()
        private_key_bytes = base64.b64decode(data["private_key"])
        signing_key = nacl.signing.SigningKey(private_key_bytes[:32])
        return data["did"], signing_key

    def _sign(self, signing_key, message: str) -> str:
        import base64
        signed = signing_key.sign(message.encode('utf-8'))
        return base64.b64encode(signed.signature).decode()

    def test_new_format_with_timestamp(self):
        """Message with new signing format succeeds."""
        import base64 as b64
        client = get_test_client()
        sender_did, sender_key = self._register_agent("sender1")
        recip_did, _ = self._register_agent("recip1")

        from datetime import datetime, timezone
        timestamp = datetime.now(timezone.utc).isoformat()
        content = b64.b64encode(b"hello encrypted").decode()
        payload = f"{sender_did}|{recip_did}|{timestamp}|{content}"
        signature = self._sign(sender_key, payload)

        resp = client.post("/message", json={
            "sender_did": sender_did,
            "recipient_did": recip_did,
            "encrypted_content": content,
            "signature": signature,
            "timestamp": timestamp
        })
        assert resp.status_code == 200, f"Send failed: {resp.text}"
        data = resp.json()
        assert data["success"] is True

    def test_legacy_format_with_deprecation_warning(self):
        """Legacy signing format returns deprecation warning."""
        import base64 as b64
        client = get_test_client()
        sender_did, sender_key = self._register_agent("sender2")
        recip_did, _ = self._register_agent("recip2")

        content = b64.b64encode(b"hello legacy").decode()
        signature = self._sign(sender_key, content)

        resp = client.post("/message", json={
            "sender_did": sender_did,
            "recipient_did": recip_did,
            "encrypted_content": content,
            "signature": signature
        })
        assert resp.status_code == 200, f"Send failed: {resp.text}"
        data = resp.json()
        assert data["success"] is True
        assert data.get("deprecation_warning") is not None
        assert "DEPRECATED" in data["deprecation_warning"]

    def test_replay_rejected(self):
        """Duplicate signed message is rejected."""
        import base64 as b64
        client = get_test_client()
        sender_did, sender_key = self._register_agent("sender3")
        recip_did, _ = self._register_agent("recip3")

        from datetime import datetime, timezone
        timestamp = datetime.now(timezone.utc).isoformat()
        content = b64.b64encode(b"hello replay").decode()
        payload = f"{sender_did}|{recip_did}|{timestamp}|{content}"
        signature = self._sign(sender_key, payload)

        msg = {
            "sender_did": sender_did,
            "recipient_did": recip_did,
            "encrypted_content": content,
            "signature": signature,
            "timestamp": timestamp
        }

        resp1 = client.post("/message", json=msg)
        assert resp1.status_code == 200

        resp2 = client.post("/message", json=msg)
        assert resp2.status_code == 409, f"Expected 409 for replay, got {resp2.status_code}"

    def test_stale_timestamp_rejected(self):
        """Message with timestamp >5min old is rejected."""
        import base64 as b64
        client = get_test_client()
        sender_did, sender_key = self._register_agent("sender4")
        recip_did, _ = self._register_agent("recip4")

        from datetime import datetime, timezone, timedelta
        old_time = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
        content = b64.b64encode(b"hello stale").decode()
        payload = f"{sender_did}|{recip_did}|{old_time}|{content}"
        signature = self._sign(sender_key, payload)

        resp = client.post("/message", json={
            "sender_did": sender_did,
            "recipient_did": recip_did,
            "encrypted_content": content,
            "signature": signature,
            "timestamp": old_time
        })
        assert resp.status_code == 400, f"Expected 400 for stale timestamp, got {resp.status_code}"


class TestVouchCertificateValid:
    """Test valid vouch certificate export and verification (Task 1.1 gap)."""

    def test_valid_certificate_roundtrip(self):
        """Register two agents, vouch, export certificate, verify it."""
        import base64
        import nacl.signing
        client = get_test_client()

        # Register voucher
        r1 = client.post("/register/easy", json={
            "platform": "test", "username": f"cert_voucher_{uuid.uuid4().hex[:8]}"
        })
        assert r1.status_code == 200
        voucher_did = r1.json()["did"]
        voucher_sk = nacl.signing.SigningKey(base64.b64decode(r1.json()["private_key"])[:32])

        # Register target
        r2 = client.post("/register/easy", json={
            "platform": "test", "username": f"cert_target_{uuid.uuid4().hex[:8]}"
        })
        assert r2.status_code == 200
        target_did = r2.json()["did"]

        # Create vouch with proper signature
        scope = "GENERAL"
        statement = "I trust this agent"
        payload = f"{voucher_did}|{target_did}|{scope}|{statement}"
        signed = voucher_sk.sign(payload.encode('utf-8'))
        signature = base64.b64encode(signed.signature).decode()

        vouch_resp = client.post("/vouch", json={
            "voucher_did": voucher_did,
            "target_did": target_did,
            "scope": scope,
            "statement": statement,
            "signature": signature
        })
        assert vouch_resp.status_code == 200, f"Vouch failed: {vouch_resp.text}"
        vouch_id = vouch_resp.json()["vouch_id"]

        # Export certificate
        cert_resp = client.get(f"/vouch/certificate/{vouch_id}")
        assert cert_resp.status_code == 200, f"Certificate export failed: {cert_resp.text}"
        cert = cert_resp.json()

        # Verify certificate
        verify_resp = client.post("/vouch/verify-certificate", json=cert)
        assert verify_resp.status_code == 200, f"Certificate verify failed: {verify_resp.text}"
        data = verify_resp.json()
        assert data["valid"] is True, f"Certificate not valid: {data}"


class TestKeyRotation:
    """Test key rotation flow (Task 1.4 gap)."""

    def test_rotate_key_and_verify(self):
        """Register, rotate key, verify new key is returned."""
        import base64
        import nacl.signing
        client = get_test_client()

        # Register agent
        reg = client.post("/register/easy", json={
            "platform": "test", "username": f"rotate_{uuid.uuid4().hex[:8]}"
        })
        assert reg.status_code == 200
        did = reg.json()["did"]
        old_sk = nacl.signing.SigningKey(base64.b64decode(reg.json()["private_key"])[:32])

        # Generate new keypair
        new_sk = nacl.signing.SigningKey.generate()
        new_public_b64 = base64.b64encode(new_sk.verify_key.encode()).decode()

        # Sign rotation request with OLD key
        rotation_payload = f"rotate:{new_public_b64}"
        signed = old_sk.sign(rotation_payload.encode('utf-8'))
        signature = base64.b64encode(signed.signature).decode()

        # Rotate key
        rotate_resp = client.post("/rotate-key", json={
            "did": did,
            "new_public_key": new_public_b64,
            "signature": signature
        })
        assert rotate_resp.status_code == 200, f"Rotation failed: {rotate_resp.text}"

        # Verify new key is returned
        verify_resp = client.get("/verify", params={"did": did})
        assert verify_resp.status_code == 200, f"Verify failed: {verify_resp.text}"
        data = verify_resp.json()
        assert data["public_key"] == new_public_b64
        assert data["key_rotated"] is True


class TestRevouchAfterRevocation:
    """Test re-vouch after revocation (Task 2.3 gap)."""

    def test_revouch_same_scope_succeeds(self):
        """After revoking a vouch, vouching again with same scope should succeed."""
        import base64
        import nacl.signing
        client = get_test_client()

        # Register two agents
        r1 = client.post("/register/easy", json={
            "platform": "test", "username": f"revouch_a_{uuid.uuid4().hex[:8]}"
        })
        assert r1.status_code == 200
        a_did = r1.json()["did"]
        a_sk = nacl.signing.SigningKey(base64.b64decode(r1.json()["private_key"])[:32])

        r2 = client.post("/register/easy", json={
            "platform": "test", "username": f"revouch_b_{uuid.uuid4().hex[:8]}"
        })
        assert r2.status_code == 200
        b_did = r2.json()["did"]

        scope = "GENERAL"
        statement = "trust"

        # Vouch A→B
        payload = f"{a_did}|{b_did}|{scope}|{statement}"
        sig = base64.b64encode(a_sk.sign(payload.encode('utf-8')).signature).decode()
        vouch_resp = client.post("/vouch", json={
            "voucher_did": a_did, "target_did": b_did,
            "scope": scope, "statement": statement, "signature": sig
        })
        assert vouch_resp.status_code == 200, f"First vouch failed: {vouch_resp.text}"
        vouch_id = vouch_resp.json()["vouch_id"]

        # Revoke (sign the vouch_id)
        revoke_sig = base64.b64encode(a_sk.sign(vouch_id.encode('utf-8')).signature).decode()
        revoke_resp = client.post("/revoke", json={
            "vouch_id": vouch_id,
            "voucher_did": a_did,
            "signature": revoke_sig
        })
        assert revoke_resp.status_code == 200, f"Revoke failed: {revoke_resp.text}"

        # Re-vouch A→B with same scope — should succeed (not 409)
        payload2 = f"{a_did}|{b_did}|{scope}|{statement}"
        sig2 = base64.b64encode(a_sk.sign(payload2.encode('utf-8')).signature).decode()
        revouch_resp = client.post("/vouch", json={
            "voucher_did": a_did, "target_did": b_did,
            "scope": scope, "statement": statement, "signature": sig2
        })
        assert revouch_resp.status_code == 200, f"Re-vouch failed (got {revouch_resp.status_code}): {revouch_resp.text}"


class TestCleanup:
    """Test database cleanup functions."""

    def test_cleanup_old_messages(self):
        """Test that old read messages are cleaned up."""
        client = get_test_client()
        import database
        from datetime import datetime, timedelta

        # Register two agents
        resp1 = client.post("/register/easy", json={
            "platform": "test", "username": "cleanup_sender", "display_name": "Sender"
        })
        resp2 = client.post("/register/easy", json={
            "platform": "test", "username": "cleanup_recipient", "display_name": "Recipient"
        })
        sender_did = resp1.json()["did"]
        recipient_did = resp2.json()["did"]

        # Insert a message directly and backdate it
        old_date = (datetime.utcnow() - timedelta(days=45)).isoformat()
        with database.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO messages (id, sender_did, recipient_did, encrypted_content, signature, created_at, read_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                ("old-msg-1", sender_did, recipient_did, "encrypted", "sig", old_date, old_date)
            )
            conn.commit()

        # Cleanup should remove it (read + older than 30 days)
        removed = database.cleanup_old_messages(ttl_days=30)
        assert removed >= 1

    def test_cleanup_expired_challenges(self):
        """Test that expired challenges are removed."""
        import database
        from datetime import datetime, timedelta

        with database.get_connection() as conn:
            cursor = conn.cursor()
            expired = (datetime.utcnow() - timedelta(hours=1)).isoformat()
            cursor.execute(
                "INSERT OR IGNORE INTO challenges (did, challenge, expires_at) VALUES (?, ?, ?)",
                ("did:aip:test_cleanup", "old-challenge", expired)
            )
            conn.commit()

        removed = database.cleanup_expired_challenges()
        assert removed >= 1

    def test_run_all_cleanup(self):
        """Test the combined cleanup runner."""
        import database
        stats = database.run_all_cleanup()
        assert "expired_challenges_removed" in stats
        assert "expired_vouches_removed" in stats
        assert "old_messages_removed" in stats
        assert "inbox_trimmed_messages" in stats

    def test_health_includes_cleanup(self):
        """Test that /health endpoint includes cleanup info."""
        client = get_test_client()
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert "cleanup" in data


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
        TestVouchCertificateForgery,
        TestMessageReplayProtection,
        TestCleanup
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
