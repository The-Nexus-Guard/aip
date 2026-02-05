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
        # First register to get a valid DID
        unique_username = f"ChallengeTest_{uuid.uuid4().hex[:8]}"
        reg_response = requests.post(
            f"{AIP_SERVICE}/register/easy",
            json={"platform": "moltbook", "username": unique_username}
        )
        assert reg_response.status_code == 200
        did = reg_response.json()["did"]

        # Now create challenge for that DID
        response = requests.post(
            f"{AIP_SERVICE}/challenge",
            json={"did": did}
        )
        assert response.status_code == 200, f"Got {response.status_code}: {response.text}"
        data = response.json()
        assert "challenge" in data
        assert data["did"] == did
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
        """Can get empty trust graph for new agent."""
        # Register a new agent
        unique_username = f"TrustTest_{uuid.uuid4().hex[:8]}"
        reg_response = requests.post(
            f"{AIP_SERVICE}/register/easy",
            json={"platform": "moltbook", "username": unique_username}
        )
        assert reg_response.status_code == 200
        did = reg_response.json()["did"]

        # Get trust graph (should be empty)
        response = requests.get(
            f"{AIP_SERVICE}/trust-graph",
            params={"did": did}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["did"] == did
        assert data["vouched_by"] == []
        assert data["vouches_for"] == []

    def test_get_trust_graph_unregistered_fails(self):
        """Getting trust graph for unregistered DID fails."""
        response = requests.get(
            f"{AIP_SERVICE}/trust-graph",
            params={"did": "did:aip:nonexistent12345"}
        )
        assert response.status_code == 404

    def test_vouch_invalid_scope_fails(self):
        """Vouching with invalid scope fails."""
        # Create two agents
        agent1 = f"Voucher_{uuid.uuid4().hex[:8]}"
        agent2 = f"Target_{uuid.uuid4().hex[:8]}"

        reg1 = requests.post(
            f"{AIP_SERVICE}/register/easy",
            json={"platform": "moltbook", "username": agent1}
        ).json()

        reg2 = requests.post(
            f"{AIP_SERVICE}/register/easy",
            json={"platform": "moltbook", "username": agent2}
        ).json()

        # Try to vouch with invalid scope (signature doesn't matter if scope check fails first)
        response = requests.post(
            f"{AIP_SERVICE}/vouch",
            json={
                "voucher_did": reg1["did"],
                "target_did": reg2["did"],
                "scope": "INVALID_SCOPE",
                "signature": "fake_sig"
            }
        )
        assert response.status_code == 400
        assert "Invalid scope" in response.json()["detail"]

    def test_vouch_self_fails(self):
        """Cannot vouch for yourself."""
        agent = f"SelfVouch_{uuid.uuid4().hex[:8]}"
        reg = requests.post(
            f"{AIP_SERVICE}/register/easy",
            json={"platform": "moltbook", "username": agent}
        ).json()

        response = requests.post(
            f"{AIP_SERVICE}/vouch",
            json={
                "voucher_did": reg["did"],
                "target_did": reg["did"],
                "scope": "GENERAL",
                "signature": "fake_sig"
            }
        )
        assert response.status_code == 400
        assert "Cannot vouch for yourself" in response.json()["detail"]


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
        # Register an agent first
        unique_username = f"RotateTest_{uuid.uuid4().hex[:8]}"
        reg = requests.post(
            f"{AIP_SERVICE}/register/easy",
            json={"platform": "moltbook", "username": unique_username}
        ).json()

        # Try to rotate with a fake signature
        response = requests.post(
            f"{AIP_SERVICE}/rotate-key",
            json={
                "did": reg["did"],
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
        assert data["status"] == "ok"
        assert "timestamp" in data


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
        TestKeyRotation,
        TestExplorer
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
