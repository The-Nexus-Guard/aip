"""
Agent Identity Protocol - Core Identity Module

Provides cryptographic identity for AI agents using Ed25519 keypairs.
"""

import json
import hashlib
import base64
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any

# Try PyNaCl first (faster), fall back to pure Python
try:
    from nacl.signing import SigningKey, VerifyKey
    from nacl.encoding import Base64Encoder
    from nacl.exceptions import BadSignatureError
    CRYPTO_BACKEND = "pynacl"
except ImportError:
    try:
        from .pure_ed25519 import Ed25519Key
        CRYPTO_BACKEND = "pure_python"
    except ImportError:
        # Try absolute import for direct script execution
        try:
            from pure_ed25519 import Ed25519Key
            CRYPTO_BACKEND = "pure_python"
        except ImportError:
            CRYPTO_BACKEND = None


class AgentIdentity:
    """
    Represents an agent's cryptographic identity.

    Each agent has:
    - A unique identifier (derived from public key)
    - An Ed25519 keypair for signing/verification
    - A DID document describing the agent
    """

    def __init__(self, name: str, key_material: Any, metadata: Optional[Dict] = None):
        self.name = name
        self._key = key_material
        self.metadata = metadata or {}
        self.created_at = datetime.now(timezone.utc)

    @property
    def public_key(self) -> str:
        """Base64-encoded public key."""
        if CRYPTO_BACKEND == "pynacl":
            return self._key.verify_key.encode(encoder=Base64Encoder).decode('utf-8')
        else:
            return base64.b64encode(self._key.public_key).decode('utf-8')

    @property
    def public_key_bytes(self) -> bytes:
        """Raw public key bytes."""
        if CRYPTO_BACKEND == "pynacl":
            return bytes(self._key.verify_key)
        else:
            return self._key.public_key

    @property
    def did(self) -> str:
        """
        Decentralized Identifier for this agent.
        Format: did:aip:<base64-public-key-hash>
        """
        key_hash = hashlib.sha256(self.public_key_bytes).hexdigest()[:32]
        return f"did:aip:{key_hash}"

    @property
    def did_key(self) -> str:
        """
        W3C did:key identifier for this agent.
        Format: did:key:z<base58btc(multicodec-ed25519-pub + public-key-bytes)>

        This provides interoperability with MCP-I, DIF standards, and any
        system that supports the did:key method (W3C CCG specification).
        """
        return public_key_to_did_key(self.public_key_bytes)

    @classmethod
    def create(cls, name: str, metadata: Optional[Dict] = None) -> 'AgentIdentity':
        """Create a new agent identity with fresh keypair."""
        if CRYPTO_BACKEND is None:
            raise RuntimeError("No crypto backend available. Install pynacl or ensure pure_ed25519.py is present.")

        if CRYPTO_BACKEND == "pynacl":
            key = SigningKey.generate()
        else:
            key = Ed25519Key.generate()

        return cls(name, key, metadata)

    @classmethod
    def from_private_key(cls, name: str, private_key_b64: str, metadata: Optional[Dict] = None) -> 'AgentIdentity':
        """Restore identity from a saved private key."""
        if CRYPTO_BACKEND is None:
            raise RuntimeError("No crypto backend available.")

        private_key_bytes = base64.b64decode(private_key_b64)

        if CRYPTO_BACKEND == "pynacl":
            key = SigningKey(private_key_bytes)
        else:
            key = Ed25519Key.from_seed(private_key_bytes)

        return cls(name, key, metadata)

    def sign(self, message: bytes) -> str:
        """Sign a message with this agent's private key. Returns base64 signature."""
        if isinstance(message, str):
            message = message.encode('utf-8')

        if CRYPTO_BACKEND == "pynacl":
            signed = self._key.sign(message, encoder=Base64Encoder)
            return signed.signature.decode('utf-8')
        else:
            signature = self._key.sign(message)
            return base64.b64encode(signature).decode('utf-8')

    def sign_json(self, data: Dict) -> Dict:
        """Sign a JSON payload, adding signature and signer info."""
        payload = json.dumps(data, sort_keys=True, separators=(',', ':'))
        signature = self.sign(payload.encode('utf-8'))
        return {
            "payload": data,
            "signature": signature,
            "signer": self.did,
            "signed_at": datetime.now(timezone.utc).isoformat()
        }

    @staticmethod
    def verify(public_key_b64: str, message: bytes, signature_b64: str) -> bool:
        """Verify a signature against a public key."""
        if CRYPTO_BACKEND is None:
            raise RuntimeError("No crypto backend available.")

        if isinstance(message, str):
            message = message.encode('utf-8')

        try:
            public_key_bytes = base64.b64decode(public_key_b64)
            signature = base64.b64decode(signature_b64)

            if CRYPTO_BACKEND == "pynacl":
                verify_key = VerifyKey(public_key_bytes)
                verify_key.verify(message, signature)
                return True
            else:
                return Ed25519Key.verify_with_public_key(public_key_bytes, message, signature)
        except Exception:
            return False

    def create_did_document(self) -> Dict[str, Any]:
        """
        Generate a DID Document for this agent.

        Follows W3C DID Core spec structure, adapted for agents.
        """
        doc = {
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1"
            ],
            "id": self.did,
            "controller": self.did,
            "verificationMethod": [{
                "id": f"{self.did}#keys-1",
                "type": "Ed25519VerificationKey2020",
                "controller": self.did,
                "publicKeyBase64": self.public_key
            }],
            "authentication": [f"{self.did}#keys-1"],
            "assertionMethod": [f"{self.did}#keys-1"],
            "service": [{
                "id": f"{self.did}#agent",
                "type": "AIAgent",
                "serviceEndpoint": {
                    "name": self.name,
                    "created": self.created_at.isoformat(),
                    "metadata": self.metadata
                }
            }]
        }

        # Add alsoKnownAs with did:key for W3C/MCP-I interoperability
        try:
            doc["alsoKnownAs"] = [self.did_key]
        except Exception:
            pass  # base58 not available — skip did:key alias

        return doc

    def export_private_key(self) -> str:
        """Export private key as base64. KEEP THIS SECRET."""
        if CRYPTO_BACKEND == "pynacl":
            return base64.b64encode(bytes(self._key)).decode('utf-8')
        else:
            return base64.b64encode(self._key.secret_key).decode('utf-8')

    def save(self, directory: str) -> None:
        """Save identity to files (private key + DID document)."""
        path = Path(directory)
        path.mkdir(parents=True, exist_ok=True)

        # Save private key (SENSITIVE!)
        key_file = path / f"{self.name}.key"
        key_file.write_text(self.export_private_key())
        key_file.chmod(0o600)  # Owner read/write only

        # Save DID document (public)
        did_file = path / f"{self.name}.did.json"
        did_file.write_text(json.dumps(self.create_did_document(), indent=2))

    @classmethod
    def load(cls, directory: str, name: str) -> 'AgentIdentity':
        """Load identity from saved files."""
        path = Path(directory)
        key_file = path / f"{name}.key"
        did_file = path / f"{name}.did.json"

        private_key_b64 = key_file.read_text().strip()
        did_doc = json.loads(did_file.read_text())

        metadata = {}
        for service in did_doc.get("service", []):
            if service.get("type") == "AIAgent":
                metadata = service.get("serviceEndpoint", {}).get("metadata", {})
                break

        return cls.from_private_key(name, private_key_b64, metadata)


class VerificationChallenge:
    """
    Challenge-response protocol for agent-to-agent verification.
    """

    @staticmethod
    def create_challenge() -> Dict[str, str]:
        """Create a verification challenge."""
        import secrets
        nonce = secrets.token_hex(32)
        timestamp = datetime.now(timezone.utc).isoformat()
        return {
            "type": "aip-challenge-v1",
            "nonce": nonce,
            "timestamp": timestamp,
            "expires_in_seconds": 300
        }

    @staticmethod
    def respond_to_challenge(identity: AgentIdentity, challenge: Dict) -> Dict:
        """Sign a challenge to prove identity."""
        challenge_bytes = json.dumps(challenge, sort_keys=True).encode('utf-8')
        signature = identity.sign(challenge_bytes)
        return {
            "challenge": challenge,
            "response": {
                "signer_did": identity.did,
                "public_key": identity.public_key,
                "signature": signature
            }
        }

    @staticmethod
    def verify_response(challenge: Dict, response: Dict) -> bool:
        """Verify a challenge response."""
        challenge_bytes = json.dumps(challenge, sort_keys=True).encode('utf-8')
        public_key = response["response"]["public_key"]
        signature = response["response"]["signature"]
        return AgentIdentity.verify(public_key, challenge_bytes, signature)


# Convenience functions
def create_agent(name: str, **metadata) -> AgentIdentity:
    """Create a new agent identity."""
    return AgentIdentity.create(name, metadata)


def verify_signature(public_key: str, message: bytes, signature: str) -> bool:
    """Verify a signature."""
    return AgentIdentity.verify(public_key, message, signature)


def get_backend() -> str:
    """Return which crypto backend is in use."""
    return CRYPTO_BACKEND or "none"


# --- did:key support (W3C CCG / MCP-I interoperability) ---

# Multicodec varint prefix for ed25519-pub: 0xed 0x01
_ED25519_MULTICODEC_PREFIX = bytes([0xed, 0x01])


def public_key_to_did_key(public_key_bytes: bytes) -> str:
    """
    Convert an Ed25519 public key to a did:key identifier.

    Uses the W3C CCG did:key method specification:
    - Multicodec prefix 0xed01 for ed25519-pub
    - Multibase 'z' prefix for base58btc encoding

    Args:
        public_key_bytes: Raw 32-byte Ed25519 public key

    Returns:
        did:key:z... string
    """
    try:
        import base58
    except ImportError:
        raise RuntimeError("base58 package required for did:key support. Install: pip install base58")

    if len(public_key_bytes) != 32:
        raise ValueError(f"Ed25519 public key must be 32 bytes, got {len(public_key_bytes)}")

    multicodec_key = _ED25519_MULTICODEC_PREFIX + public_key_bytes
    encoded = base58.b58encode(multicodec_key).decode('ascii')
    return f"did:key:z{encoded}"


def did_key_to_public_key(did_key: str) -> bytes:
    """
    Extract an Ed25519 public key from a did:key identifier.

    Args:
        did_key: did:key:z... string

    Returns:
        Raw 32-byte Ed25519 public key

    Raises:
        ValueError: If the DID is not a valid did:key with Ed25519 key
    """
    try:
        import base58
    except ImportError:
        raise RuntimeError("base58 package required for did:key support. Install: pip install base58")

    if not did_key.startswith("did:key:z"):
        raise ValueError(f"Invalid did:key format: must start with 'did:key:z', got '{did_key[:20]}...'")

    encoded = did_key[len("did:key:z"):]
    decoded = base58.b58decode(encoded)

    if len(decoded) < 2:
        raise ValueError("did:key payload too short")

    if decoded[:2] != _ED25519_MULTICODEC_PREFIX:
        raise ValueError(
            f"Unsupported key type. Expected Ed25519 multicodec prefix "
            f"(0xed01), got 0x{decoded[0]:02x}{decoded[1]:02x}"
        )

    public_key_bytes = decoded[2:]
    if len(public_key_bytes) != 32:
        raise ValueError(f"Expected 32-byte Ed25519 key, got {len(public_key_bytes)} bytes")

    return public_key_bytes


def resolve_did(did: str) -> Optional[Dict[str, Any]]:
    """
    Resolve a DID to its public key information.

    Supports:
    - did:aip:<hash> — requires API lookup (returns None, use client.verify)
    - did:key:z<base58btc> — self-resolving, extracts key directly

    Returns:
        Dict with 'public_key_bytes' and 'public_key_b64', or None if not resolvable locally.
    """
    if did.startswith("did:key:z"):
        pk_bytes = did_key_to_public_key(did)
        return {
            "did": did,
            "public_key_bytes": pk_bytes,
            "public_key_b64": base64.b64encode(pk_bytes).decode('utf-8'),
            "method": "key",
            "key_type": "Ed25519"
        }
    elif did.startswith("did:aip:"):
        # did:aip requires server lookup — not locally resolvable
        return None
    else:
        return None
