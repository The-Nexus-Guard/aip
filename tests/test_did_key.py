"""Tests for did:key interoperability (W3C CCG / MCP-I compatibility)."""

import base64
import pytest
from aip_identity.identity import (
    AgentIdentity,
    public_key_to_did_key,
    did_key_to_public_key,
    resolve_did,
)


class TestDidKeyConversion:
    """Test did:key encoding and decoding."""

    def test_roundtrip(self):
        """Public key → did:key → public key roundtrip."""
        identity = AgentIdentity.create("test-agent")
        pk_bytes = identity.public_key_bytes

        did_key = public_key_to_did_key(pk_bytes)
        recovered = did_key_to_public_key(did_key)

        assert recovered == pk_bytes

    def test_did_key_format(self):
        """did:key starts with 'did:key:z'."""
        identity = AgentIdentity.create("test-agent")
        did_key = identity.did_key

        assert did_key.startswith("did:key:z")
        # z prefix + base58btc encoded (multicodec prefix + 32 bytes)
        # Should be roughly 48-50 chars after "did:key:"
        assert len(did_key) > len("did:key:z") + 40

    def test_identity_has_both_dids(self):
        """AgentIdentity exposes both did:aip and did:key."""
        identity = AgentIdentity.create("dual-did")

        assert identity.did.startswith("did:aip:")
        assert identity.did_key.startswith("did:key:z")
        # Both derive from the same key
        assert did_key_to_public_key(identity.did_key) == identity.public_key_bytes

    def test_deterministic(self):
        """Same key always produces same did:key."""
        identity = AgentIdentity.create("test")
        assert identity.did_key == identity.did_key

        # Also from raw bytes
        pk = identity.public_key_bytes
        assert public_key_to_did_key(pk) == public_key_to_did_key(pk)

    def test_different_keys_different_dids(self):
        """Different keys produce different did:key identifiers."""
        id1 = AgentIdentity.create("agent-1")
        id2 = AgentIdentity.create("agent-2")
        assert id1.did_key != id2.did_key

    def test_invalid_key_length(self):
        """Reject non-32-byte keys."""
        with pytest.raises(ValueError, match="32 bytes"):
            public_key_to_did_key(b"too-short")

        with pytest.raises(ValueError, match="32 bytes"):
            public_key_to_did_key(b"x" * 64)

    def test_invalid_did_key_format(self):
        """Reject malformed did:key strings."""
        with pytest.raises(ValueError, match="Invalid did:key format"):
            did_key_to_public_key("did:aip:abc123")

        with pytest.raises(ValueError, match="Invalid did:key format"):
            did_key_to_public_key("not-a-did")

    def test_wrong_multicodec_prefix(self):
        """Reject did:key with non-Ed25519 multicodec."""
        import base58
        # Use P-256 prefix (0x80, 0x24) instead of Ed25519 (0xed, 0x01)
        fake = bytes([0x80, 0x24]) + b'\x00' * 32
        encoded = base58.b58encode(fake).decode('ascii')
        fake_did = f"did:key:z{encoded}"

        with pytest.raises(ValueError, match="Unsupported key type"):
            did_key_to_public_key(fake_did)


class TestResolveDid:
    """Test DID resolution."""

    def test_resolve_did_key(self):
        """did:key resolves locally to public key info."""
        identity = AgentIdentity.create("test")
        result = resolve_did(identity.did_key)

        assert result is not None
        assert result["method"] == "key"
        assert result["key_type"] == "Ed25519"
        assert result["public_key_bytes"] == identity.public_key_bytes
        assert result["public_key_b64"] == identity.public_key

    def test_resolve_did_aip_returns_none(self):
        """did:aip requires server lookup, returns None."""
        result = resolve_did("did:aip:c1965a89866ecbfa")
        assert result is None

    def test_resolve_unknown_method(self):
        """Unknown DID methods return None."""
        assert resolve_did("did:web:example.com") is None
        assert resolve_did("did:ion:abc123") is None

    def test_resolve_roundtrip_verify(self):
        """Resolved did:key can be used to verify signatures."""
        identity = AgentIdentity.create("signer")
        message = b"test message for verification"
        signature = identity.sign(message)

        # Resolve the did:key
        resolved = resolve_did(identity.did_key)
        assert resolved is not None

        # Verify using the resolved public key
        assert AgentIdentity.verify(resolved["public_key_b64"], message, signature)


class TestDidKeyInterop:
    """Test interoperability scenarios."""

    def test_known_test_vector(self):
        """Verify against a known Ed25519 did:key test vector."""
        # Known test: all-zeros public key
        import base58
        zero_key = b'\x00' * 32
        prefix = bytes([0xed, 0x01])
        encoded = base58.b58encode(prefix + zero_key).decode('ascii')
        expected_did = f"did:key:z{encoded}"

        assert public_key_to_did_key(zero_key) == expected_did
        assert did_key_to_public_key(expected_did) == zero_key

    def test_from_private_key_preserves_did_key(self):
        """Restoring from private key produces same did:key."""
        original = AgentIdentity.create("persistent")
        pk_b64 = original.export_private_key()
        did_key_original = original.did_key

        restored = AgentIdentity.from_private_key("persistent", pk_b64)
        assert restored.did_key == did_key_original

    def test_signature_verified_via_did_key_resolution(self):
        """Full flow: sign with AIP identity, verify via did:key resolution."""
        # Agent signs something
        agent = AgentIdentity.create("mcp-agent")
        payload = b'{"action": "book_flight", "destination": "SFO"}'
        sig = agent.sign(payload)

        # Another party has only the did:key
        their_did_key = agent.did_key

        # They resolve it and verify
        resolved = resolve_did(their_did_key)
        assert AgentIdentity.verify(resolved["public_key_b64"], payload, sig)
