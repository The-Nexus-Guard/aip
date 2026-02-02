#!/usr/bin/env python3
"""
AIP Test Suite

Run with: python3 -m pytest tests/ -v
Or directly: python3 tests/test_aip.py
"""

import sys
import tempfile
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from identity import AgentIdentity, VerificationChallenge, get_backend
from trust import (
    TrustGraph, TrustLevel, TrustScope, Vouch, Revocation, TrustPath,
    verify_vouch, verify_trust_path
)


class TestIdentity:
    """Tests for the identity layer."""

    def test_create_identity(self):
        """Agents can create unique identities."""
        alice = AgentIdentity.create("Alice")
        bob = AgentIdentity.create("Bob")

        assert alice.did.startswith("did:aip:")
        assert bob.did.startswith("did:aip:")
        assert alice.did != bob.did
        assert alice.name == "Alice"

    def test_identity_with_metadata(self):
        """Identities can include metadata."""
        agent = AgentIdentity.create("Agent", {"role": "analyst", "version": "1.0"})

        assert agent.metadata["role"] == "analyst"
        did_doc = agent.create_did_document()
        assert did_doc["service"][0]["serviceEndpoint"]["metadata"]["role"] == "analyst"

    def test_sign_and_verify(self):
        """Messages can be signed and verified."""
        alice = AgentIdentity.create("Alice")
        message = b"Hello, World!"

        signature = alice.sign(message)

        assert AgentIdentity.verify(alice.public_key, message, signature)

    def test_verify_wrong_key_fails(self):
        """Verification with wrong key fails."""
        alice = AgentIdentity.create("Alice")
        bob = AgentIdentity.create("Bob")
        message = b"Hello, World!"

        signature = alice.sign(message)

        assert not AgentIdentity.verify(bob.public_key, message, signature)

    def test_verify_tampered_message_fails(self):
        """Verification of tampered message fails."""
        alice = AgentIdentity.create("Alice")
        message = b"Hello, World!"

        signature = alice.sign(message)
        tampered = b"Hello, World!!"

        assert not AgentIdentity.verify(alice.public_key, tampered, signature)

    def test_sign_json(self):
        """JSON payloads can be signed."""
        alice = AgentIdentity.create("Alice")
        data = {"action": "transfer", "amount": 100}

        signed = alice.sign_json(data)

        assert signed["payload"] == data
        assert signed["signer"] == alice.did
        assert "signature" in signed

    def test_challenge_response(self):
        """Challenge-response protocol verifies identity."""
        alice = AgentIdentity.create("Alice")
        bob = AgentIdentity.create("Bob")

        # Alice creates challenge for Bob
        challenge = VerificationChallenge.create_challenge()
        assert "nonce" in challenge

        # Bob responds
        response = VerificationChallenge.respond_to_challenge(bob, challenge)

        # Alice verifies
        assert VerificationChallenge.verify_response(challenge, response)

    def test_challenge_response_wrong_agent_fails(self):
        """Challenge response from different agent fails."""
        alice = AgentIdentity.create("Alice")
        bob = AgentIdentity.create("Bob")
        carol = AgentIdentity.create("Carol")

        challenge = VerificationChallenge.create_challenge()
        response = VerificationChallenge.respond_to_challenge(bob, challenge)

        # Tamper with response to claim it's from Carol
        response["response"]["public_key"] = carol.public_key

        assert not VerificationChallenge.verify_response(challenge, response)

    def test_save_and_load(self):
        """Identities can be saved and loaded."""
        alice = AgentIdentity.create("Alice", {"test": True})

        with tempfile.TemporaryDirectory() as tmpdir:
            alice.save(tmpdir)

            # Check files exist
            assert (Path(tmpdir) / "Alice.key").exists()
            assert (Path(tmpdir) / "Alice.did.json").exists()

            # Load and verify
            loaded = AgentIdentity.load(tmpdir, "Alice")
            assert loaded.did == alice.did
            assert loaded.public_key == alice.public_key
            assert loaded.name == "Alice"

    def test_export_private_key(self):
        """Private key can be exported and reimported."""
        alice = AgentIdentity.create("Alice")
        private_key = alice.export_private_key()

        restored = AgentIdentity.from_private_key("Alice", private_key)

        assert restored.did == alice.did
        assert restored.public_key == alice.public_key


class TestTrust:
    """Tests for the trust layer."""

    def test_create_trust_graph(self):
        """Agents can create trust graphs."""
        alice = AgentIdentity.create("Alice")
        trust = TrustGraph(alice)

        assert trust.my_did == alice.did
        assert len(trust.vouches) == 0

    def test_vouch_for_agent(self):
        """Agents can vouch for each other."""
        alice = AgentIdentity.create("Alice")
        bob = AgentIdentity.create("Bob")
        alice_trust = TrustGraph(alice)

        vouch = alice_trust.vouch_for(bob, statement="Bob is trustworthy")

        assert vouch.voucher_did == alice.did
        assert vouch.target_did == bob.did
        assert vouch.level == TrustLevel.STRONG
        assert verify_vouch(vouch)

    def test_vouch_with_scope(self):
        """Vouches can have specific scopes."""
        alice = AgentIdentity.create("Alice")
        bob = AgentIdentity.create("Bob")
        alice_trust = TrustGraph(alice)

        vouch = alice_trust.vouch_for(
            bob,
            scope=TrustScope.CODE_SIGNING,
            level=TrustLevel.STRONG
        )

        assert vouch.scope == TrustScope.CODE_SIGNING

    def test_direct_trust(self):
        """Direct vouches create STRONG trust."""
        alice = AgentIdentity.create("Alice")
        bob = AgentIdentity.create("Bob")
        alice_trust = TrustGraph(alice)

        alice_trust.vouch_for(bob)

        trusted, path = alice_trust.check_trust(bob.did)
        assert trusted
        assert path.trust_level == TrustLevel.STRONG
        assert path.length == 1

    def test_transitive_trust(self):
        """Trust flows through vouch chains."""
        alice = AgentIdentity.create("Alice")
        bob = AgentIdentity.create("Bob")
        carol = AgentIdentity.create("Carol")

        alice_trust = TrustGraph(alice)
        bob_trust = TrustGraph(bob)

        # Alice trusts Bob, Bob trusts Carol
        alice_trust.vouch_for(bob)
        bob_vouch = bob_trust.vouch_for(carol)

        # Alice learns about Bob's vouch
        alice_trust.import_vouch(Vouch.from_dict(bob_vouch.to_dict()))

        # Alice should trust Carol via Bob
        trusted, path = alice_trust.check_trust(carol.did)
        assert trusted
        assert path.length == 2
        assert path.trust_level == TrustLevel.MODERATE

    def test_no_trust_path(self):
        """Unknown agents have no trust path."""
        alice = AgentIdentity.create("Alice")
        stranger = AgentIdentity.create("Stranger")
        alice_trust = TrustGraph(alice)

        trusted, path = alice_trust.check_trust(stranger.did)

        assert not trusted
        assert path is None
        assert alice_trust.get_trust_level(stranger.did) == TrustLevel.UNKNOWN

    def test_revoke_vouch(self):
        """Vouches can be revoked."""
        alice = AgentIdentity.create("Alice")
        bob = AgentIdentity.create("Bob")
        alice_trust = TrustGraph(alice)

        vouch = alice_trust.vouch_for(bob)
        assert alice_trust.check_trust(bob.did)[0]

        alice_trust.revoke_vouch(vouch.vouch_id, "Trust withdrawn")

        assert not alice_trust.check_trust(bob.did)[0]

    def test_revocation_breaks_chain(self):
        """Revoking a vouch breaks downstream trust paths."""
        alice = AgentIdentity.create("Alice")
        bob = AgentIdentity.create("Bob")
        carol = AgentIdentity.create("Carol")

        alice_trust = TrustGraph(alice)
        bob_trust = TrustGraph(bob)

        vouch1 = alice_trust.vouch_for(bob)
        vouch2 = bob_trust.vouch_for(carol)
        alice_trust.import_vouch(Vouch.from_dict(vouch2.to_dict()))

        # Before revocation
        assert alice_trust.check_trust(carol.did)[0]

        # Revoke Alice's trust in Bob
        alice_trust.revoke_vouch(vouch1.vouch_id)

        # Carol is no longer trusted (path broken)
        assert not alice_trust.check_trust(carol.did)[0]

    def test_trust_path_verification(self):
        """Trust paths can be cryptographically verified."""
        alice = AgentIdentity.create("Alice")
        bob = AgentIdentity.create("Bob")
        carol = AgentIdentity.create("Carol")

        alice_trust = TrustGraph(alice)
        bob_trust = TrustGraph(bob)

        alice_trust.vouch_for(bob)
        bob_vouch = bob_trust.vouch_for(carol)
        alice_trust.import_vouch(Vouch.from_dict(bob_vouch.to_dict()))

        _, path = alice_trust.check_trust(carol.did)

        assert verify_trust_path(path)

    def test_export_import_trust_graph(self):
        """Trust graphs can be exported and imported."""
        alice = AgentIdentity.create("Alice")
        bob = AgentIdentity.create("Bob")
        alice_trust = TrustGraph(alice)

        alice_trust.vouch_for(bob, statement="Test vouch")

        exported = alice_trust.to_dict()

        assert len(exported["vouches"]) == 1
        assert exported["identity"] == alice.did

    def test_vouch_expiration(self):
        """Expired vouches are not valid."""
        from datetime import timedelta

        alice = AgentIdentity.create("Alice")
        bob = AgentIdentity.create("Bob")

        # Create a vouch that expires in -1 days (already expired)
        vouch = Vouch(
            voucher_did=alice.did,
            voucher_pubkey=alice.public_key,
            target_did=bob.did,
            target_pubkey=bob.public_key,
            scope=TrustScope.GENERAL,
            level=TrustLevel.STRONG,
            statement="Test",
            created_at=(datetime.now(timezone.utc) - timedelta(days=2)).isoformat(),
            expires_at=(datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        )

        assert vouch.is_expired()

    def test_get_vouches_for_agent(self):
        """Can retrieve all vouches for a specific agent."""
        alice = AgentIdentity.create("Alice")
        bob = AgentIdentity.create("Bob")
        carol = AgentIdentity.create("Carol")

        alice_trust = TrustGraph(alice)
        carol_trust = TrustGraph(carol)

        alice_trust.vouch_for(bob)
        carol_vouch = carol_trust.vouch_for(bob)
        alice_trust.import_vouch(Vouch.from_dict(carol_vouch.to_dict()))

        vouches = alice_trust.get_vouches_for(bob.did)

        assert len(vouches) == 2


class TestIntegration:
    """Integration tests combining identity and trust."""

    def test_full_workflow(self):
        """Complete workflow: create, verify, vouch, check trust."""
        # Create agents
        alice = AgentIdentity.create("Alice")
        bob = AgentIdentity.create("Bob")
        carol = AgentIdentity.create("Carol")

        # Alice verifies Bob's identity
        challenge = VerificationChallenge.create_challenge()
        response = VerificationChallenge.respond_to_challenge(bob, challenge)
        assert VerificationChallenge.verify_response(challenge, response)

        # Alice vouches for Bob after verification
        alice_trust = TrustGraph(alice)
        alice_trust.vouch_for(bob, statement="Verified Bob's identity")

        # Bob vouches for Carol
        bob_trust = TrustGraph(bob)
        bob_vouch = bob_trust.vouch_for(carol)

        # Alice imports Bob's vouch
        alice_trust.import_vouch(Vouch.from_dict(bob_vouch.to_dict()))

        # Alice can now trust Carol transitively
        trusted, path = alice_trust.check_trust(carol.did)
        assert trusted
        assert path.trust_level == TrustLevel.MODERATE
        assert verify_trust_path(path)


# Import datetime for expiration test
from datetime import datetime, timezone


def run_tests():
    """Run all tests manually (without pytest)."""
    import traceback

    test_classes = [TestIdentity, TestTrust, TestIntegration]
    passed = 0
    failed = 0

    print(f"AIP Test Suite (backend: {get_backend()})")
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
