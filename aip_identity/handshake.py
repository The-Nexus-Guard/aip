"""
Agent Trust Handshake Protocol

A self-contained 3-round-trip HTTP protocol for two agents to mutually verify
each other's identity using Ed25519 challenge-response. No central authority
needed.

Protocol flow:
  1. INITIATE: Agent A sends their DID + public key + a challenge nonce
  2. RESPOND: Agent B verifies A, sends their DID + public key + signed response + counter-challenge
  3. CONFIRM: Agent A verifies B, sends signed response to counter-challenge

After 3 rounds, both agents have verified each other's Ed25519 identities.
The result is a HandshakeResult with both DIDs and a shared session token.

Usage:
    from aip_identity.handshake import HandshakeInitiator, HandshakeResponder

    # Agent A (initiator)
    initiator = HandshakeInitiator(identity_a)
    msg1 = initiator.create_initiate()
    # Send msg1 to Agent B, get msg2 back
    msg3 = initiator.process_response(msg2)
    # Send msg3 to Agent B
    result = initiator.result  # HandshakeResult

    # Agent B (responder)
    responder = HandshakeResponder(identity_b)
    msg2 = responder.process_initiate(msg1)
    # Send msg2 to Agent A, get msg3 back
    responder.process_confirm(msg3)
    result = responder.result  # HandshakeResult
"""

import hashlib
import json
import os
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

# Try PyNaCl first, fall back to pure Python
try:
    from nacl.signing import SigningKey, VerifyKey
    from nacl.encoding import RawEncoder
    from nacl.exceptions import BadSignatureError
    CRYPTO_BACKEND = "pynacl"
except ImportError:
    CRYPTO_BACKEND = "pure_python"


PROTOCOL_VERSION = "aip-handshake-v1"
CHALLENGE_BYTES = 32
NONCE_EXPIRY_SECONDS = 300  # 5 minutes


class HandshakeError(Exception):
    """Raised when handshake verification fails."""
    pass


@dataclass
class HandshakeResult:
    """Result of a successful mutual handshake."""
    my_did: str
    peer_did: str
    peer_public_key: str
    session_token: str  # Shared token derived from both challenges
    timestamp: float
    protocol_version: str = PROTOCOL_VERSION

    def to_dict(self) -> Dict[str, Any]:
        return {
            "my_did": self.my_did,
            "peer_did": self.peer_did,
            "peer_public_key": self.peer_public_key,
            "session_token": self.session_token,
            "timestamp": self.timestamp,
            "protocol_version": self.protocol_version,
        }


def _generate_challenge() -> str:
    """Generate a random challenge nonce (hex-encoded)."""
    return os.urandom(CHALLENGE_BYTES).hex()


def _sign_message(private_key_hex: str, message: str) -> str:
    """Sign a message with Ed25519, return hex-encoded signature."""
    private_key_bytes = bytes.fromhex(private_key_hex)

    if CRYPTO_BACKEND == "pynacl":
        signing_key = SigningKey(private_key_bytes[:32])
        signed = signing_key.sign(message.encode("utf-8"), encoder=RawEncoder)
        return signed.signature.hex()
    else:
        from .pure_ed25519 import Ed25519Key
        key = Ed25519Key(private_key_bytes[:32])
        sig = key.sign(message.encode("utf-8"))
        return sig.hex()


def _verify_signature(public_key_hex: str, message: str, signature_hex: str) -> bool:
    """Verify an Ed25519 signature. Returns True if valid."""
    try:
        public_key_bytes = bytes.fromhex(public_key_hex)
        signature_bytes = bytes.fromhex(signature_hex)

        if CRYPTO_BACKEND == "pynacl":
            verify_key = VerifyKey(public_key_bytes)
            verify_key.verify(message.encode("utf-8"), signature_bytes)
            return True
        else:
            from .pure_ed25519 import Ed25519Key
            return Ed25519Key.verify_with_public_key(
                public_key_bytes, message.encode("utf-8"), signature_bytes
            )
    except Exception:
        return False


def _derive_session_token(challenge_a: str, challenge_b: str) -> str:
    """Derive a shared session token from both challenges."""
    combined = f"{challenge_a}:{challenge_b}"
    return hashlib.sha256(combined.encode()).hexdigest()


def _compute_did(public_key_hex: str) -> str:
    """Compute DID from public key hex."""
    public_key_bytes = bytes.fromhex(public_key_hex)
    did_hash = hashlib.sha256(public_key_bytes).hexdigest()[:32]
    return f"did:aip:{did_hash}"


class HandshakeInitiator:
    """
    Initiator side of the trust handshake.

    Usage:
        initiator = HandshakeInitiator(my_did, my_public_key_hex, my_private_key_hex)
        msg1 = initiator.create_initiate()
        # ... send msg1, receive msg2 ...
        msg3 = initiator.process_response(msg2)
        # ... send msg3 ...
        result = initiator.result
    """

    def __init__(self, did: str, public_key_hex: str, private_key_hex: str):
        self.did = did
        self.public_key = public_key_hex
        self._private_key = private_key_hex
        self._challenge: Optional[str] = None
        self._peer_challenge: Optional[str] = None
        self._result: Optional[HandshakeResult] = None
        self._timestamp: float = 0

    @classmethod
    def from_identity(cls, identity) -> "HandshakeInitiator":
        """Create from an AgentIdentity instance."""
        return cls(
            did=identity.did,
            public_key_hex=identity.public_key,
            private_key_hex=identity.private_key_hex,
        )

    def create_initiate(self) -> Dict[str, Any]:
        """
        Step 1: Create the initiation message.

        Returns a dict to send to the responder.
        """
        self._challenge = _generate_challenge()
        self._timestamp = time.time()

        payload = {
            "protocol": PROTOCOL_VERSION,
            "step": "initiate",
            "did": self.did,
            "public_key": self.public_key,
            "challenge": self._challenge,
            "timestamp": self._timestamp,
        }
        return payload

    def process_response(self, msg: Dict[str, Any]) -> Dict[str, Any]:
        """
        Step 3: Process the responder's response, create confirmation.

        Verifies the responder signed our challenge correctly,
        then signs their counter-challenge.

        Returns a dict to send back as confirmation.
        Raises HandshakeError if verification fails.
        """
        if self._challenge is None:
            raise HandshakeError("Must call create_initiate() first")

        # Validate message structure
        if msg.get("protocol") != PROTOCOL_VERSION:
            raise HandshakeError(f"Protocol mismatch: {msg.get('protocol')}")
        if msg.get("step") != "respond":
            raise HandshakeError(f"Expected 'respond' step, got '{msg.get('step')}'")

        peer_did = msg.get("did")
        peer_public_key = msg.get("public_key")
        peer_signature = msg.get("signature")
        peer_challenge = msg.get("counter_challenge")

        if not all([peer_did, peer_public_key, peer_signature, peer_challenge]):
            raise HandshakeError("Missing required fields in response")

        # Verify peer's DID matches their public key
        expected_did = _compute_did(peer_public_key)
        if peer_did != expected_did:
            raise HandshakeError(
                f"DID mismatch: claimed {peer_did}, computed {expected_did}"
            )

        # Verify peer signed our challenge
        sign_payload = f"{PROTOCOL_VERSION}:respond:{self._challenge}:{peer_did}"
        if not _verify_signature(peer_public_key, sign_payload, peer_signature):
            raise HandshakeError("Invalid signature on challenge response")

        # Check timestamp freshness
        peer_timestamp = msg.get("timestamp", 0)
        if abs(time.time() - peer_timestamp) > NONCE_EXPIRY_SECONDS:
            raise HandshakeError("Response timestamp expired")

        # Sign the counter-challenge
        self._peer_challenge = peer_challenge
        confirm_payload = f"{PROTOCOL_VERSION}:confirm:{peer_challenge}:{self.did}"
        signature = _sign_message(self._private_key, confirm_payload)

        # Derive session token
        session_token = _derive_session_token(self._challenge, peer_challenge)

        self._result = HandshakeResult(
            my_did=self.did,
            peer_did=peer_did,
            peer_public_key=peer_public_key,
            session_token=session_token,
            timestamp=time.time(),
        )

        return {
            "protocol": PROTOCOL_VERSION,
            "step": "confirm",
            "did": self.did,
            "signature": signature,
            "timestamp": time.time(),
        }

    @property
    def result(self) -> Optional[HandshakeResult]:
        return self._result


class HandshakeResponder:
    """
    Responder side of the trust handshake.

    Usage:
        responder = HandshakeResponder(my_did, my_public_key_hex, my_private_key_hex)
        msg2 = responder.process_initiate(msg1)
        # ... send msg2, receive msg3 ...
        responder.process_confirm(msg3)
        result = responder.result
    """

    def __init__(self, did: str, public_key_hex: str, private_key_hex: str):
        self.did = did
        self.public_key = public_key_hex
        self._private_key = private_key_hex
        self._peer_challenge: Optional[str] = None
        self._counter_challenge: Optional[str] = None
        self._peer_did: Optional[str] = None
        self._peer_public_key: Optional[str] = None
        self._result: Optional[HandshakeResult] = None

    @classmethod
    def from_identity(cls, identity) -> "HandshakeResponder":
        """Create from an AgentIdentity instance."""
        return cls(
            did=identity.did,
            public_key_hex=identity.public_key,
            private_key_hex=identity.private_key_hex,
        )

    def process_initiate(self, msg: Dict[str, Any]) -> Dict[str, Any]:
        """
        Step 2: Process initiation, create response with counter-challenge.

        Verifies the initiator's identity and creates a signed response.

        Returns a dict to send back.
        Raises HandshakeError if verification fails.
        """
        # Validate message structure
        if msg.get("protocol") != PROTOCOL_VERSION:
            raise HandshakeError(f"Protocol mismatch: {msg.get('protocol')}")
        if msg.get("step") != "initiate":
            raise HandshakeError(f"Expected 'initiate' step, got '{msg.get('step')}'")

        peer_did = msg.get("did")
        peer_public_key = msg.get("public_key")
        peer_challenge = msg.get("challenge")

        if not all([peer_did, peer_public_key, peer_challenge]):
            raise HandshakeError("Missing required fields in initiation")

        # Verify peer's DID matches their public key
        expected_did = _compute_did(peer_public_key)
        if peer_did != expected_did:
            raise HandshakeError(
                f"DID mismatch: claimed {peer_did}, computed {expected_did}"
            )

        # Check timestamp freshness
        peer_timestamp = msg.get("timestamp", 0)
        if abs(time.time() - peer_timestamp) > NONCE_EXPIRY_SECONDS:
            raise HandshakeError("Initiation timestamp expired")

        # Store peer info
        self._peer_did = peer_did
        self._peer_public_key = peer_public_key
        self._peer_challenge = peer_challenge

        # Generate counter-challenge
        self._counter_challenge = _generate_challenge()

        # Sign the peer's challenge
        sign_payload = f"{PROTOCOL_VERSION}:respond:{peer_challenge}:{self.did}"
        signature = _sign_message(self._private_key, sign_payload)

        return {
            "protocol": PROTOCOL_VERSION,
            "step": "respond",
            "did": self.did,
            "public_key": self.public_key,
            "signature": signature,
            "counter_challenge": self._counter_challenge,
            "timestamp": time.time(),
        }

    def process_confirm(self, msg: Dict[str, Any]) -> None:
        """
        Step 4: Process the initiator's confirmation.

        Verifies the initiator signed our counter-challenge.

        Raises HandshakeError if verification fails.
        """
        if self._counter_challenge is None:
            raise HandshakeError("Must call process_initiate() first")

        # Validate message structure
        if msg.get("protocol") != PROTOCOL_VERSION:
            raise HandshakeError(f"Protocol mismatch: {msg.get('protocol')}")
        if msg.get("step") != "confirm":
            raise HandshakeError(f"Expected 'confirm' step, got '{msg.get('step')}'")

        peer_did = msg.get("did")
        peer_signature = msg.get("signature")

        if not all([peer_did, peer_signature]):
            raise HandshakeError("Missing required fields in confirmation")

        # Verify it's the same peer
        if peer_did != self._peer_did:
            raise HandshakeError(
                f"DID mismatch: expected {self._peer_did}, got {peer_did}"
            )

        # Verify signature on our counter-challenge
        confirm_payload = f"{PROTOCOL_VERSION}:confirm:{self._counter_challenge}:{peer_did}"
        if not _verify_signature(self._peer_public_key, confirm_payload, peer_signature):
            raise HandshakeError("Invalid signature on confirmation")

        # Derive session token (same as initiator)
        session_token = _derive_session_token(self._peer_challenge, self._counter_challenge)

        self._result = HandshakeResult(
            my_did=self.did,
            peer_did=self._peer_did,
            peer_public_key=self._peer_public_key,
            session_token=session_token,
            timestamp=time.time(),
        )

    @property
    def result(self) -> Optional[HandshakeResult]:
        return self._result


def perform_handshake(identity_a, identity_b) -> tuple:
    """
    Convenience function: perform a full handshake between two local identities.

    Returns (result_a, result_b) — the HandshakeResult for each side.

    Useful for testing and demonstrations.
    """
    initiator = HandshakeInitiator.from_identity(identity_a)
    responder = HandshakeResponder.from_identity(identity_b)

    # Round 1: A → B
    msg1 = initiator.create_initiate()

    # Round 2: B → A
    msg2 = responder.process_initiate(msg1)

    # Round 3: A → B
    msg3 = initiator.process_response(msg2)

    # B processes confirmation
    responder.process_confirm(msg3)

    return initiator.result, responder.result
