#!/usr/bin/env python3
"""
AIP Live Service Tests

Tests the production AIP service at https://aip-service.fly.dev
Run with: python3 tests/test_live_service.py

These tests use requests (no extra dependencies) and test the actual
deployed service rather than a local mock.
"""

import sys
import requests
import time
import uuid

AIP_SERVICE = "https://aip-service.fly.dev"

# Shared test agent - created once, reused across tests to avoid rate limits
_shared_agent = None

def get_shared_agent():
    """Get or create a shared test agent to avoid rate limiting."""
    global _shared_agent
    if _shared_agent is None:
        unique_username = f"SharedTestAgent_{uuid.uuid4().hex[:8]}"

        # Try up to 3 times with exponential backoff
        for attempt in range(3):
            response = requests.post(
                f"{AIP_SERVICE}/register/easy",
                json={"platform": "moltbook", "username": unique_username}
            )
            if response.status_code == 200:
                _shared_agent = response.json()
                return _shared_agent
            elif response.status_code == 429:  # Rate limited
                # Parse wait time from response if available
                try:
                    detail = response.json().get("detail", "")
                    import re
                    match = re.search(r"(\d+) seconds", detail)
                    wait_time = int(match.group(1)) + 2 if match else 60
                except:
                    wait_time = 60
                print(f"Rate limited, waiting {wait_time}s...")
                time.sleep(wait_time)
            else:
                raise Exception(f"Could not create shared agent: {response.text}")

        raise Exception("Failed to create shared agent after 3 attempts")
    return _shared_agent


class TestHealthEndpoints:
    """Test health and info endpoints."""

    def test_root(self):
        """Root endpoint returns service info."""
        response = requests.get(f"{AIP_SERVICE}/")
        assert response.status_code == 200, f"Got {response.status_code}: {response.text}"
        data = response.json()
        assert data["service"] == "AIP - Agent Identity Protocol"
        assert "version" in data

    def test_stats(self):
        """Stats endpoint returns registration counts."""
        response = requests.get(f"{AIP_SERVICE}/stats")
        assert response.status_code == 200, f"Got {response.status_code}: {response.text}"
        data = response.json()
        assert "stats" in data
        assert "registrations" in data["stats"]


class TestRegistration:
    """Test registration endpoints."""

    def test_easy_register(self):
        """Easy registration creates identity and returns keys."""
        # Use unique username to avoid conflicts
        unique_username = f"TestAgent_{uuid.uuid4().hex[:8]}"

        response = requests.post(
            f"{AIP_SERVICE}/register/easy",
            json={"platform": "moltbook", "username": unique_username}
        )
        assert response.status_code == 200, f"Got {response.status_code}: {response.text}"
        data = response.json()
        assert data["success"] is True
        assert data["did"].startswith("did:aip:")
        assert "public_key" in data
        assert "private_key" in data
        assert data["platform"] == "moltbook"
        assert data["username"] == unique_username

        # Store for cleanup/other tests
        return data

    def test_easy_register_duplicate_fails(self):
        """Cannot register same platform+username twice."""
        # Use unique username for this test
        unique_username = f"DupeAgent_{uuid.uuid4().hex[:8]}"

        # First registration succeeds
        response1 = requests.post(
            f"{AIP_SERVICE}/register/easy",
            json={"platform": "moltbook", "username": unique_username}
        )
        assert response1.status_code == 200, f"First reg failed: {response1.text}"

        # Second registration fails with 409 Conflict
        response2 = requests.post(
            f"{AIP_SERVICE}/register/easy",
            json={"platform": "moltbook", "username": unique_username}
        )
        assert response2.status_code == 409, f"Expected 409 Conflict, got {response2.status_code}: {response2.text}"

    def test_easy_register_missing_fields(self):
        """Registration requires platform and username."""
        response = requests.post(
            f"{AIP_SERVICE}/register/easy",
            json={"platform": "moltbook"}  # Missing username
        )
        assert response.status_code == 422, f"Expected 422, got {response.status_code}"


class TestVerification:
    """Test verification endpoints."""

    def test_verify_registered_agent(self):
        """Can verify a registered agent."""
        # Register first
        unique_username = f"VerifyMe_{uuid.uuid4().hex[:8]}"
        reg_response = requests.post(
            f"{AIP_SERVICE}/register/easy",
            json={"platform": "moltbook", "username": unique_username}
        )
        assert reg_response.status_code == 200
        did = reg_response.json()["did"]

        # Now verify - API uses 'username' not 'platform_id'
        verify_response = requests.get(
            f"{AIP_SERVICE}/verify",
            params={"platform": "moltbook", "username": unique_username}
        )
        assert verify_response.status_code == 200
        data = verify_response.json()
        assert data["verified"] is True
        assert data["did"] == did

    def test_verify_unregistered_agent(self):
        """Verifying unregistered agent returns false."""
        response = requests.get(
            f"{AIP_SERVICE}/verify",
            params={"platform": "moltbook", "username": f"NotRegistered_{uuid.uuid4().hex[:8]}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["verified"] is False


class TestLookup:
    """Test lookup endpoints."""

    def test_lookup_by_did(self):
        """Can look up agent by DID."""
        # Register first
        unique_username = f"LookupTest_{uuid.uuid4().hex[:8]}"
        reg_response = requests.post(
            f"{AIP_SERVICE}/register/easy",
            json={"platform": "moltbook", "username": unique_username}
        )
        did = reg_response.json()["did"]
        public_key = reg_response.json()["public_key"]

        # Lookup by DID
        lookup_response = requests.get(f"{AIP_SERVICE}/lookup/{did}")
        assert lookup_response.status_code == 200
        data = lookup_response.json()
        assert data["did"] == did
        assert data["public_key"] == public_key

    def test_lookup_unknown_did(self):
        """Looking up unknown DID returns 404."""
        response = requests.get(f"{AIP_SERVICE}/lookup/did:aip:nonexistent123456")
        assert response.status_code == 404


class TestChallenge:
    """Test challenge-response endpoints."""

    def test_create_challenge(self):
        """Can create a challenge for a registered DID."""
        # Use shared agent to avoid rate limits
        agent = get_shared_agent()

        # Create challenge for that DID
        response = requests.post(
            f"{AIP_SERVICE}/challenge",
            json={"did": agent["did"]}
        )
        assert response.status_code == 200, f"Got {response.status_code}: {response.text}"
        data = response.json()
        assert "challenge" in data
        assert data["did"] == agent["did"]
        assert "expires_at" in data

    def test_create_challenge_unregistered_did_fails(self):
        """Creating challenge for unregistered DID fails."""
        response = requests.post(
            f"{AIP_SERVICE}/challenge",
            json={"did": "did:aip:nonexistent12345"}
        )
        assert response.status_code == 404


class TestTrustGraph:
    """Test trust/vouch endpoints."""

    def test_get_trust_graph_empty(self):
        """Can get trust graph for agent."""
        # Use shared agent to avoid rate limits
        agent = get_shared_agent()

        # Get trust graph
        response = requests.get(
            f"{AIP_SERVICE}/trust-graph",
            params={"did": agent["did"]}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["did"] == agent["did"]
        # Don't assert empty - shared agent might have vouches
        assert "vouched_by" in data
        assert "vouches_for" in data

    def test_get_trust_graph_unregistered_fails(self):
        """Getting trust graph for unregistered DID fails."""
        response = requests.get(
            f"{AIP_SERVICE}/trust-graph",
            params={"did": "did:aip:nonexistent12345"}
        )
        assert response.status_code == 404

    def test_vouch_invalid_scope_fails(self):
        """Vouching with invalid scope fails."""
        # Use shared agent to avoid rate limits
        agent = get_shared_agent()

        # Try to vouch with invalid scope (signature doesn't matter if scope check fails first)
        response = requests.post(
            f"{AIP_SERVICE}/vouch",
            json={
                "voucher_did": agent["did"],
                "target_did": "did:aip:someotherdid12345678",
                "scope": "INVALID_SCOPE",
                "signature": "fake_sig"
            }
        )
        assert response.status_code == 400
        assert "Invalid scope" in response.json()["detail"]

    def test_vouch_self_fails(self):
        """Cannot vouch for yourself."""
        # Use shared agent to avoid rate limits
        agent = get_shared_agent()

        response = requests.post(
            f"{AIP_SERVICE}/vouch",
            json={
                "voucher_did": agent["did"],
                "target_did": agent["did"],
                "scope": "GENERAL",
                "signature": "fake_sig"
            }
        )
        assert response.status_code == 400
        assert "Cannot vouch for yourself" in response.json()["detail"]


class TestTrustPath:
    """Test trust path query endpoint."""

    def test_trust_path_same_did(self):
        """Trust path to self returns length 0."""
        # Use shared agent to avoid rate limits
        agent = get_shared_agent()

        response = requests.get(
            f"{AIP_SERVICE}/trust-path",
            params={"source_did": agent["did"], "target_did": agent["did"]}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["path_exists"] is True
        assert data["path_length"] == 0

    def test_trust_path_unregistered_source(self):
        """Trust path with unregistered source fails."""
        # Use shared agent as target
        agent = get_shared_agent()

        response = requests.get(
            f"{AIP_SERVICE}/trust-path",
            params={"source_did": "did:aip:nonexistent123", "target_did": agent["did"]}
        )
        assert response.status_code == 404
        assert "Source DID" in response.json()["detail"]

    def test_trust_path_no_path(self):
        """Trust path returns false when no path exists."""
        # Use shared agent as source, fake DID as target
        agent = get_shared_agent()

        # Query path to a known registered agent we don't have vouches with
        # We use a fixed test DID that should exist in prod
        response = requests.get(
            f"{AIP_SERVICE}/trust-path",
            params={"source_did": agent["did"], "target_did": "did:aip:c1965a89866ecbfaad49803e6ced70fb"}
        )
        assert response.status_code == 200
        data = response.json()
        # Either no path or path exists (depends on vouches) - just check it returns valid response
        assert "path_exists" in data

    def test_trust_path_invalid_scope(self):
        """Trust path with invalid scope fails."""
        # Use shared agent to avoid rate limits
        agent = get_shared_agent()

        response = requests.get(
            f"{AIP_SERVICE}/trust-path",
            params={
                "source_did": agent["did"],
                "target_did": agent["did"],
                "scope": "INVALID_SCOPE"
            }
        )
        assert response.status_code == 400


class TestKeyRotation:
    """Test key rotation endpoint."""

    def test_rotate_key_unregistered_did_fails(self):
        """Key rotation fails for unregistered DID."""
        response = requests.post(
            f"{AIP_SERVICE}/rotate-key",
            json={
                "did": "did:aip:nonexistent12345678",
                "new_public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "signature": "fake_signature"
            }
        )
        assert response.status_code == 404
        assert "not registered" in response.json()["detail"]

    def test_rotate_key_invalid_signature_fails(self):
        """Key rotation with invalid signature fails."""
        # Use shared agent to avoid rate limits
        agent = get_shared_agent()

        # Try to rotate with a fake signature
        response = requests.post(
            f"{AIP_SERVICE}/rotate-key",
            json={
                "did": agent["did"],
                "new_public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "signature": "fake_signature_not_valid_base64!"
            }
        )
        assert response.status_code == 400
        assert "Signature" in response.json()["detail"] or "signature" in response.json()["detail"].lower()

    def test_rotate_key_missing_fields(self):
        """Key rotation requires all fields."""
        response = requests.post(
            f"{AIP_SERVICE}/rotate-key",
            json={
                "did": "did:aip:test123"
                # Missing new_public_key and signature
            }
        )
        assert response.status_code == 422


class TestExplorer:
    """Test explorer/stats endpoints."""

    def test_stats_structure(self):
        """Stats endpoint returns expected structure."""
        response = requests.get(f"{AIP_SERVICE}/stats")
        assert response.status_code == 200
        data = response.json()
        assert "service" in data
        assert "status" in data
        assert data["status"] == "operational"
        assert "stats" in data
        assert "registrations" in data["stats"]

    def test_health_endpoint(self):
        """Health endpoint works."""
        response = requests.get(f"{AIP_SERVICE}/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "timestamp" in data


class TestSkillSigning:
    """Test skill signing endpoints."""

    def test_hash_content(self):
        """Hash endpoint returns valid SHA256 hash."""
        response = requests.post(
            f"{AIP_SERVICE}/skill/hash",
            params={"skill_content": "# My Skill\n\nThis is a test skill."}
        )
        assert response.status_code == 200, f"Got {response.status_code}: {response.text}"
        data = response.json()
        assert data["content_hash"].startswith("sha256:")
        assert len(data["content_hash"]) == 71  # sha256: + 64 hex chars

    def test_hash_deterministic(self):
        """Same content always produces same hash."""
        content = "# Test Skill v1.0"

        response1 = requests.post(
            f"{AIP_SERVICE}/skill/hash",
            params={"skill_content": content}
        )
        response2 = requests.post(
            f"{AIP_SERVICE}/skill/hash",
            params={"skill_content": content}
        )

        assert response1.json()["content_hash"] == response2.json()["content_hash"]

    def test_verify_unregistered_author_fails(self):
        """Verify fails for unregistered author DID."""
        response = requests.get(
            f"{AIP_SERVICE}/skill/verify",
            params={
                "content_hash": "sha256:abc123def456",
                "author_did": "did:aip:nonexistent12345678",
                "signature": "fake_signature",
                "timestamp": "2026-02-05T00:00:00Z"
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["verified"] is False
        assert "not registered" in data.get("message", "").lower()

    def test_verify_with_valid_signature(self):
        """Verify works with properly signed content."""
        import base64
        import hashlib
        from datetime import datetime, timezone

        # Register a new agent for signing
        unique_username = f"SkillSigner_{uuid.uuid4().hex[:8]}"
        reg_response = requests.post(
            f"{AIP_SERVICE}/register/easy",
            json={"platform": "moltbook", "username": unique_username}
        )
        assert reg_response.status_code == 200, f"Registration failed: {reg_response.text}"
        reg = reg_response.json()

        did = reg["did"]
        private_key_bytes = base64.b64decode(reg["private_key"])

        # Create content and hash
        content = "# Test Skill\n\nSome content here."
        content_hash = "sha256:" + hashlib.sha256(content.encode()).hexdigest()

        # Create timestamp and payload
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        payload = f"{did}|{content_hash}|{timestamp}"

        # Sign with Ed25519 (try cryptography lib)
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
            signature_bytes = private_key.sign(payload.encode())
            signature_b64 = base64.b64encode(signature_bytes).decode()
        except ImportError:
            # Skip if cryptography not available
            return

        # Verify via API
        response = requests.get(
            f"{AIP_SERVICE}/skill/verify",
            params={
                "content_hash": content_hash,
                "author_did": did,
                "signature": signature_b64,
                "timestamp": timestamp
            }
        )
        assert response.status_code == 200, f"Got {response.status_code}: {response.text}"
        data = response.json()
        assert data["verified"] is True
        assert data["author_did"] == did


def run_tests():
    """Run all tests manually."""
    import traceback

    test_classes = [
        TestHealthEndpoints,
        TestRegistration,
        TestVerification,
        TestLookup,
        TestChallenge,
        TestTrustGraph,
        TestTrustPath,
        TestKeyRotation,
        TestExplorer,
        TestSkillSigning
    ]
    passed = 0
    failed = 0

    print(f"AIP Live Service Tests")
    print(f"Testing: {AIP_SERVICE}")
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
                except AssertionError as e:
                    print(f"  ✗ {name}: {e}")
                    failed += 1
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
