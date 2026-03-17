"""Tests for the Agent Trust Handshake Protocol."""

import hashlib
import time
import pytest

from aip_identity.handshake import (
    HandshakeInitiator,
    HandshakeResponder,
    HandshakeResult,
    HandshakeError,
    perform_handshake,
    PROTOCOL_VERSION,
    _generate_challenge,
    _sign_message,
    _verify_signature,
    _derive_session_token,
    _compute_did,
    NONCE_EXPIRY_SECONDS,
)

# Try PyNaCl for key generation
try:
    from nacl.signing import SigningKey
    HAS_PYNACL = True
except ImportError:
    HAS_PYNACL = False


def _make_keypair():
    """Generate a test Ed25519 keypair."""
    if HAS_PYNACL:
        sk = SigningKey.generate()
        private_hex = sk.encode().hex()
        public_hex = sk.verify_key.encode().hex()
    else:
        import os
        from aip_identity.pure_ed25519 import Ed25519Key
        seed = os.urandom(32)
        key = Ed25519Key(seed)
        private_hex = seed.hex()
        public_hex = key.public_key_bytes().hex()
    did = _compute_did(public_hex)
    return did, public_hex, private_hex


def _make_initiator():
    did, pub, priv = _make_keypair()
    return HandshakeInitiator(did, pub, priv), did, pub, priv


def _make_responder():
    did, pub, priv = _make_keypair()
    return HandshakeResponder(did, pub, priv), did, pub, priv


class TestCryptoHelpers:
    """Test low-level crypto helper functions."""

    def test_generate_challenge_length(self):
        c = _generate_challenge()
        assert len(c) == 64  # 32 bytes = 64 hex chars

    def test_generate_challenge_unique(self):
        c1 = _generate_challenge()
        c2 = _generate_challenge()
        assert c1 != c2

    def test_sign_and_verify(self):
        _, pub, priv = _make_keypair()
        msg = "test message"
        sig = _sign_message(priv, msg)
        assert _verify_signature(pub, msg, sig)

    def test_verify_wrong_message(self):
        _, pub, priv = _make_keypair()
        sig = _sign_message(priv, "message A")
        assert not _verify_signature(pub, "message B", sig)

    def test_verify_wrong_key(self):
        _, pub1, priv1 = _make_keypair()
        _, pub2, _ = _make_keypair()
        sig = _sign_message(priv1, "test")
        assert not _verify_signature(pub2, "test", sig)

    def test_derive_session_token_deterministic(self):
        t1 = _derive_session_token("aaa", "bbb")
        t2 = _derive_session_token("aaa", "bbb")
        assert t1 == t2

    def test_derive_session_token_order_matters(self):
        t1 = _derive_session_token("aaa", "bbb")
        t2 = _derive_session_token("bbb", "aaa")
        assert t1 != t2

    def test_compute_did_format(self):
        _, pub, _ = _make_keypair()
        did = _compute_did(pub)
        assert did.startswith("did:aip:")
        assert len(did) == len("did:aip:") + 32


class TestHandshakeHappyPath:
    """Test successful handshake flows."""

    def test_full_handshake(self):
        initiator, did_a, _, _ = _make_initiator()
        responder, did_b, _, _ = _make_responder()

        msg1 = initiator.create_initiate()
        assert msg1["step"] == "initiate"
        assert msg1["did"] == did_a
        assert msg1["protocol"] == PROTOCOL_VERSION

        msg2 = responder.process_initiate(msg1)
        assert msg2["step"] == "respond"
        assert msg2["did"] == did_b

        msg3 = initiator.process_response(msg2)
        assert msg3["step"] == "confirm"
        assert msg3["did"] == did_a

        responder.process_confirm(msg3)

        # Both sides have results
        assert initiator.result is not None
        assert responder.result is not None

        # Results are consistent
        assert initiator.result.my_did == did_a
        assert initiator.result.peer_did == did_b
        assert responder.result.my_did == did_b
        assert responder.result.peer_did == did_a

        # Session tokens match
        assert initiator.result.session_token == responder.result.session_token
        assert len(initiator.result.session_token) == 64  # SHA-256 hex

    def test_perform_handshake_convenience(self):
        """Test the convenience function."""
        # Create mock identity objects
        class MockIdentity:
            def __init__(self):
                self.did, self.public_key, self.private_key_hex = _make_keypair()

        id_a = MockIdentity()
        id_b = MockIdentity()

        result_a, result_b = perform_handshake(id_a, id_b)

        assert result_a.my_did == id_a.did
        assert result_a.peer_did == id_b.did
        assert result_b.my_did == id_b.did
        assert result_b.peer_did == id_a.did
        assert result_a.session_token == result_b.session_token

    def test_result_to_dict(self):
        initiator, _, _, _ = _make_initiator()
        responder, _, _, _ = _make_responder()

        msg1 = initiator.create_initiate()
        msg2 = responder.process_initiate(msg1)
        initiator.process_response(msg2)

        d = initiator.result.to_dict()
        assert "my_did" in d
        assert "peer_did" in d
        assert "session_token" in d
        assert "protocol_version" in d
        assert d["protocol_version"] == PROTOCOL_VERSION

    def test_multiple_handshakes_different_tokens(self):
        """Each handshake should produce a different session token."""
        initiator1, _, _, _ = _make_initiator()
        responder1, _, _, _ = _make_responder()

        msg1 = initiator1.create_initiate()
        msg2 = responder1.process_initiate(msg1)
        initiator1.process_response(msg2)

        # Second handshake with same keys
        did_a, pub_a, priv_a = initiator1.did, initiator1.public_key, initiator1._private_key
        did_b, pub_b, priv_b = responder1.did, responder1.public_key, responder1._private_key

        initiator2 = HandshakeInitiator(did_a, pub_a, priv_a)
        responder2 = HandshakeResponder(did_b, pub_b, priv_b)

        msg1b = initiator2.create_initiate()
        msg2b = responder2.process_initiate(msg1b)
        initiator2.process_response(msg2b)

        # Different session tokens (random challenges)
        assert initiator1.result.session_token != initiator2.result.session_token


class TestHandshakeErrors:
    """Test handshake failure cases."""

    def test_wrong_protocol_version_initiate(self):
        responder, _, _, _ = _make_responder()
        msg = {
            "protocol": "wrong-protocol",
            "step": "initiate",
            "did": "did:aip:test",
            "public_key": "aa" * 32,
            "challenge": "bb" * 32,
            "timestamp": time.time(),
        }
        with pytest.raises(HandshakeError, match="Protocol mismatch"):
            responder.process_initiate(msg)

    def test_wrong_protocol_version_response(self):
        initiator, _, _, _ = _make_initiator()
        initiator.create_initiate()
        msg = {
            "protocol": "wrong",
            "step": "respond",
        }
        with pytest.raises(HandshakeError, match="Protocol mismatch"):
            initiator.process_response(msg)

    def test_wrong_step_initiate(self):
        responder, _, _, _ = _make_responder()
        msg = {
            "protocol": PROTOCOL_VERSION,
            "step": "respond",  # wrong step
            "did": "did:aip:test",
            "public_key": "aa" * 32,
            "challenge": "bb" * 32,
            "timestamp": time.time(),
        }
        with pytest.raises(HandshakeError, match="Expected 'initiate'"):
            responder.process_initiate(msg)

    def test_missing_fields_initiate(self):
        responder, _, _, _ = _make_responder()
        msg = {
            "protocol": PROTOCOL_VERSION,
            "step": "initiate",
            "did": "did:aip:test",
            # missing public_key and challenge
            "timestamp": time.time(),
        }
        with pytest.raises(HandshakeError, match="Missing required"):
            responder.process_initiate(msg)

    def test_did_mismatch_initiate(self):
        """DID doesn't match the public key."""
        responder, _, _, _ = _make_responder()
        _, real_pub, _ = _make_keypair()
        msg = {
            "protocol": PROTOCOL_VERSION,
            "step": "initiate",
            "did": "did:aip:00000000000000000000000000000000",  # wrong DID
            "public_key": real_pub,
            "challenge": _generate_challenge(),
            "timestamp": time.time(),
        }
        with pytest.raises(HandshakeError, match="DID mismatch"):
            responder.process_initiate(msg)

    def test_did_mismatch_response(self):
        """Responder's DID doesn't match their public key."""
        initiator, _, _, _ = _make_initiator()
        responder, did_b, pub_b, priv_b = _make_responder()

        msg1 = initiator.create_initiate()
        msg2 = responder.process_initiate(msg1)

        # Tamper with DID
        msg2["did"] = "did:aip:00000000000000000000000000000000"

        with pytest.raises(HandshakeError, match="DID mismatch"):
            initiator.process_response(msg2)

    def test_invalid_signature_response(self):
        """Responder's signature is invalid."""
        initiator, _, _, _ = _make_initiator()
        responder, _, _, _ = _make_responder()

        msg1 = initiator.create_initiate()
        msg2 = responder.process_initiate(msg1)

        # Tamper with signature
        msg2["signature"] = "00" * 64

        with pytest.raises(HandshakeError, match="Invalid signature"):
            initiator.process_response(msg2)

    def test_invalid_signature_confirm(self):
        """Initiator's confirmation signature is invalid."""
        initiator, _, _, _ = _make_initiator()
        responder, _, _, _ = _make_responder()

        msg1 = initiator.create_initiate()
        msg2 = responder.process_initiate(msg1)
        msg3 = initiator.process_response(msg2)

        # Tamper with signature
        msg3["signature"] = "00" * 64

        with pytest.raises(HandshakeError, match="Invalid signature"):
            responder.process_confirm(msg3)

    def test_expired_timestamp_initiate(self):
        """Initiation with expired timestamp."""
        responder, _, _, _ = _make_responder()
        did_a, pub_a, _ = _make_keypair()
        msg = {
            "protocol": PROTOCOL_VERSION,
            "step": "initiate",
            "did": did_a,
            "public_key": pub_a,
            "challenge": _generate_challenge(),
            "timestamp": time.time() - NONCE_EXPIRY_SECONDS - 10,
        }
        with pytest.raises(HandshakeError, match="timestamp expired"):
            responder.process_initiate(msg)

    def test_expired_timestamp_response(self):
        """Response with expired timestamp."""
        initiator, _, _, _ = _make_initiator()
        responder, _, _, _ = _make_responder()

        msg1 = initiator.create_initiate()
        msg2 = responder.process_initiate(msg1)

        # Make timestamp expired
        msg2["timestamp"] = time.time() - NONCE_EXPIRY_SECONDS - 10

        with pytest.raises(HandshakeError, match="timestamp expired"):
            initiator.process_response(msg2)

    def test_initiator_no_initiate_first(self):
        """Calling process_response before create_initiate."""
        initiator, _, _, _ = _make_initiator()
        with pytest.raises(HandshakeError, match="create_initiate"):
            initiator.process_response({})

    def test_responder_no_initiate_first(self):
        """Calling process_confirm before process_initiate."""
        responder, _, _, _ = _make_responder()
        with pytest.raises(HandshakeError, match="process_initiate"):
            responder.process_confirm({})

    def test_wrong_peer_in_confirm(self):
        """Confirmation from a different DID than expected."""
        initiator, _, _, _ = _make_initiator()
        responder, _, _, _ = _make_responder()

        msg1 = initiator.create_initiate()
        msg2 = responder.process_initiate(msg1)
        msg3 = initiator.process_response(msg2)

        # Swap DID in confirmation
        other_did, _, _ = _make_keypair()
        msg3["did"] = other_did

        with pytest.raises(HandshakeError, match="DID mismatch"):
            responder.process_confirm(msg3)

    def test_replay_attack_different_challenge(self):
        """Replaying a response with a different challenge should fail."""
        initiator, did_a, pub_a, priv_a = _make_initiator()
        responder, _, _, _ = _make_responder()

        # First handshake
        msg1 = initiator.create_initiate()
        msg2 = responder.process_initiate(msg1)

        # Start a new initiator (different challenge)
        initiator2 = HandshakeInitiator(did_a, pub_a, priv_a)
        initiator2.create_initiate()

        # Try to use old response with new initiator
        # The signature won't match because it was signed for the first challenge
        with pytest.raises(HandshakeError, match="Invalid signature"):
            initiator2.process_response(msg2)


class TestHandshakeResult:
    """Test HandshakeResult dataclass."""

    def test_result_fields(self):
        r = HandshakeResult(
            my_did="did:aip:aaa",
            peer_did="did:aip:bbb",
            peer_public_key="cc" * 32,
            session_token="dd" * 32,
            timestamp=12345.0,
        )
        assert r.my_did == "did:aip:aaa"
        assert r.peer_did == "did:aip:bbb"
        assert r.protocol_version == PROTOCOL_VERSION

    def test_to_dict_roundtrip(self):
        r = HandshakeResult(
            my_did="did:aip:aaa",
            peer_did="did:aip:bbb",
            peer_public_key="cc" * 32,
            session_token="dd" * 32,
            timestamp=12345.0,
        )
        d = r.to_dict()
        assert d["my_did"] == "did:aip:aaa"
        assert d["peer_did"] == "did:aip:bbb"
        assert d["session_token"] == "dd" * 32
        assert isinstance(d["timestamp"], float)
