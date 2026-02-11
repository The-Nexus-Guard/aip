#!/usr/bin/env python3
"""
Integration tests for the AIP Python client.

These tests run against the live service.
Run with: python3 -m pytest tests/test_client.py -v
"""

import pytest
import time
import sys
import os

# Add parent dir to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aip_client import AIPClient, AIPError


# Use local test server via fixture
pytestmark = pytest.mark.usefixtures("local_service")


class TestAIPClientRegistration:
    """Test registration functionality."""

    def test_register_new_agent(self, local_service):
        """Test registering a new agent."""
        agent_name = f"test_client_{int(time.time())}"

        client = AIPClient.register(
            platform="moltbook",
            platform_id=agent_name,
            service_url=local_service
        )

        assert client.did.startswith("did:aip:")
        assert client.public_key is not None
        assert client.private_key is not None
        assert len(client.public_key) > 20  # Base64 encoded key

    def test_save_and_load_credentials(self, local_service, tmp_path):
        """Test saving and loading credentials."""
        agent_name = f"test_save_{int(time.time())}"

        # Register
        client = AIPClient.register(
            platform="moltbook",
            platform_id=agent_name,
            service_url=local_service
        )

        # Save
        cred_file = tmp_path / "test_creds.json"
        client.save(str(cred_file))

        # Load
        loaded = AIPClient.from_file(str(cred_file))

        assert loaded.did == client.did
        assert loaded.public_key == client.public_key
        assert loaded.private_key == client.private_key


class TestAIPClientTrust:
    """Test trust lookup functionality."""

    def test_get_trust_registered_did(self, local_service):
        """Test getting trust info for a registered DID."""
        # Register an agent first so it exists locally
        registered = AIPClient.register(
            platform="moltbook",
            platform_id=f"trust_test_{int(time.time())}",
            service_url=local_service
        )
        known_did = registered.did

        # Create a minimal client for lookup
        client = AIPClient(
            did="did:aip:test",
            public_key="",
            private_key="",
            service_url=local_service
        )

        trust = client.get_trust(known_did)

        assert trust["did"] == known_did
        assert trust["registered"] == True
        assert "vouched_by" in trust
        assert "scopes" in trust
        assert "vouch_count" in trust

    def test_get_trust_unregistered_did(self, local_service):
        """Test getting trust info for an unregistered DID."""
        fake_did = "did:aip:this_does_not_exist_12345"

        client = AIPClient(
            did="did:aip:test",
            public_key="",
            private_key="",
            service_url=local_service
        )

        trust = client.get_trust(fake_did)

        assert trust["did"] == fake_did
        assert trust["registered"] == False
        assert trust["vouch_count"] == 0

    def test_is_trusted_no_vouches(self, local_service):
        """Test is_trusted returns False when no vouches exist."""
        registered = AIPClient.register(
            platform="moltbook",
            platform_id=f"trusted_test_{int(time.time())}",
            service_url=local_service
        )

        client = AIPClient(
            did="did:aip:test",
            public_key="",
            private_key="",
            service_url=local_service
        )

        result = client.is_trusted(registered.did)
        assert isinstance(result, bool)


class TestAIPClientLookup:
    """Test DID lookup functionality."""

    def test_lookup_registered_did(self, local_service):
        """Test looking up a registered DID."""
        registered = AIPClient.register(
            platform="moltbook",
            platform_id=f"lookup_test_{int(time.time())}",
            service_url=local_service
        )

        client = AIPClient(
            did="did:aip:test",
            public_key="",
            private_key="",
            service_url=local_service
        )

        result = client.lookup(registered.did)

        assert result["did"] == registered.did
        assert "public_key" in result

    def test_lookup_unregistered_did_raises(self, local_service):
        """Test that looking up unregistered DID raises error."""
        fake_did = "did:aip:definitely_not_registered"

        client = AIPClient(
            did="did:aip:test",
            public_key="",
            private_key="",
            service_url=local_service
        )

        with pytest.raises(AIPError):
            client.lookup(fake_did)


class TestAIPClientTrustPath:
    """Test trust path functionality."""

    def test_trust_path_same_did(self, local_service):
        """Test trust path to self returns 1.0 score."""
        registered = AIPClient.register(
            platform="moltbook",
            platform_id=f"path_test_{int(time.time())}",
            service_url=local_service
        )

        result = registered.get_trust_path(registered.did)

        assert result["path_exists"] == True
        assert result["path_length"] == 0
        assert result["trust_score"] == 1.0

    def test_trust_path_no_connection(self, local_service):
        """Test trust path when target DID is not registered."""
        registered = AIPClient.register(
            platform="moltbook",
            platform_id=f"path_test2_{int(time.time())}",
            service_url=local_service
        )

        with pytest.raises(AIPError):
            registered.get_trust_path("did:aip:some_random_unconnected_did")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
