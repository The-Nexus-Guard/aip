"""
AIP Client - Simple Python client for Agent Identity Protocol.

Usage:
    from aip_client import AIPClient

    # Register a new agent
    client = AIPClient.register("moltbook", "my_agent")

    # Or load existing credentials
    client = AIPClient.from_file("aip_credentials.json")

    # Prove your identity
    signature = client.sign_challenge(challenge)

    # Verify another agent
    is_valid = client.verify(other_did, challenge, signature)

    # Vouch for someone
    vouch_id = client.vouch(other_did, scope="CODE_SIGNING")
"""

import json
import base64
import hashlib
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from typing import Optional, Dict, Any, Tuple
from pathlib import Path


def _create_session(retries=3, backoff_factor=0.3, status_forcelist=(502, 503, 504)):
    """Create a requests session with retry/backoff for resilience."""
    session = requests.Session()
    retry = Retry(
        total=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
        allowed_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


class AIPClient:
    """Client for interacting with AIP service."""

    DEFAULT_SERVICE = "https://aip-service.fly.dev"

    def __init__(
        self,
        did: str,
        public_key: str,
        private_key: str,
        service_url: str = DEFAULT_SERVICE
    ):
        self.did = did
        self.public_key = public_key
        self.private_key = private_key
        self.service_url = service_url.rstrip("/")
        self._signing_key = None
        self._session = _create_session()

    @classmethod
    def register(
        cls,
        platform: str,
        platform_id: str,
        service_url: str = DEFAULT_SERVICE
    ) -> "AIPClient":
        """
        Register a new agent with AIP.

        Generates an Ed25519 keypair client-side and registers the DID.

        Args:
            platform: Platform name (e.g., "moltbook", "github")
            platform_id: Your username on that platform
            service_url: AIP service URL (default: production)

        Returns:
            AIPClient instance with credentials

        Raises:
            AIPError: If registration fails
        """
        try:
            from nacl.signing import SigningKey
        except ImportError:
            raise AIPError("PyNaCl required for registration: pip install pynacl")

        # Generate Ed25519 keypair client-side
        signing_key = SigningKey.generate()
        verify_key = signing_key.verify_key

        private_key_b64 = base64.b64encode(signing_key.encode()).decode()
        public_key_b64 = base64.b64encode(verify_key.encode()).decode()

        # Derive DID from public key (sha256 of pubkey bytes, first 32 hex chars)
        key_hash = hashlib.sha256(verify_key.encode()).hexdigest()[:32]
        did = f"did:aip:{key_hash}"

        response = _create_session().post(
            f"{service_url}/register",
            json={
                "did": did,
                "public_key": public_key_b64,
                "platform": platform,
                "username": platform_id,
            }
        )

        if response.status_code != 200:
            raise AIPError(f"Registration failed: {response.text}")

        return cls(
            did=did,
            public_key=public_key_b64,
            private_key=private_key_b64,
            service_url=service_url
        )

    @classmethod
    def from_file(cls, path: str, service_url: str = DEFAULT_SERVICE) -> "AIPClient":
        """Load credentials from a JSON file."""
        with open(path) as f:
            data = json.load(f)
        return cls(
            did=data["did"],
            public_key=data["public_key"],
            private_key=data["private_key"],
            service_url=service_url
        )

    def save(self, path: str) -> None:
        """Save credentials to a JSON file."""
        with open(path, "w") as f:
            json.dump({
                "did": self.did,
                "public_key": self.public_key,
                "private_key": self.private_key
            }, f, indent=2)

    def _get_signing_key(self):
        """Get Ed25519 signing key from private key."""
        if self._signing_key is None:
            private_bytes = base64.b64decode(self.private_key)

            # Try different crypto libraries
            try:
                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
                self._signing_key = Ed25519PrivateKey.from_private_bytes(private_bytes[:32])
                self._crypto_lib = "cryptography"
            except ImportError:
                try:
                    import nacl.signing
                    self._signing_key = nacl.signing.SigningKey(private_bytes[:32])
                    self._crypto_lib = "nacl"
                except ImportError:
                    raise AIPError("No crypto library available. Install 'cryptography' or 'pynacl'")

        return self._signing_key

    def sign(self, message: bytes) -> str:
        """Sign a message and return base64 signature."""
        key = self._get_signing_key()

        if self._crypto_lib == "cryptography":
            signature = key.sign(message)
        else:
            signature = key.sign(message).signature

        return base64.b64encode(signature).decode()

    def sign_challenge(self, challenge: str) -> str:
        """Sign a challenge string."""
        return self.sign(challenge.encode())

    def get_challenge(self, target_did: str) -> str:
        """Request a verification challenge for a DID."""
        response = self._session.post(
            f"{self.service_url}/challenge",
            json={"did": target_did}
        )

        if response.status_code != 200:
            raise AIPError(f"Challenge request failed: {response.text}")

        return response.json()["challenge"]

    def verify(self, target_did: str) -> Dict[str, Any]:
        """
        Complete verification flow for another agent.

        Args:
            target_did: DID to verify

        Returns:
            Verification result dict with 'verified', 'platform', etc.
        """
        # Get challenge
        challenge = self.get_challenge(target_did)

        # The target needs to sign this - this is for demo
        # In practice, you'd send the challenge to them
        response = self._session.post(
            f"{self.service_url}/verify_challenge",
            json={
                "did": target_did,
                "challenge": challenge,
                "signature": ""  # They provide this
            }
        )

        return response.json()

    def lookup(self, did: str) -> Dict[str, Any]:
        """Look up a DID's registration info."""
        response = self._session.get(f"{self.service_url}/lookup/{did}")

        if response.status_code != 200:
            raise AIPError(f"Lookup failed: {response.text}")

        return response.json()

    def vouch(
        self,
        target_did: str,
        scope: str = "GENERAL",
        statement: Optional[str] = None,
        ttl_days: Optional[int] = None
    ) -> str:
        """
        Create a vouch for another agent.

        Args:
            target_did: DID to vouch for
            scope: Trust scope (GENERAL, CODE_SIGNING, FINANCIAL, etc.)
            statement: Optional trust statement
            ttl_days: Optional expiration in days

        Returns:
            Vouch ID
        """
        # Build payload to sign
        payload = f"{self.did}|{target_did}|{scope}|{statement or ''}"
        signature = self.sign(payload.encode())

        data = {
            "voucher_did": self.did,
            "target_did": target_did,
            "scope": scope,
            "statement": statement,
            "signature": signature
        }
        if ttl_days:
            data["ttl_days"] = ttl_days

        response = self._session.post(f"{self.service_url}/vouch", json=data)

        if response.status_code != 200:
            raise AIPError(f"Vouch failed: {response.text}")

        return response.json()["vouch_id"]

    def revoke(self, vouch_id: str) -> Dict[str, Any]:
        """
        Revoke a vouch you previously issued.

        Args:
            vouch_id: ID of the vouch to revoke

        Returns:
            Response dict with revocation confirmation
        """
        # Sign with domain separation: "revoke:{vouch_id}"
        domain_payload = f"revoke:{vouch_id}".encode('utf-8')
        signature = self.sign(domain_payload)

        data = {
            "voucher_did": self.did,
            "vouch_id": vouch_id,
            "signature": signature
        }

        response = self._session.post(f"{self.service_url}/revoke", json=data)

        if response.status_code != 200:
            raise AIPError(f"Revoke failed: {response.text}")

        return response.json()

    def get_trust_path(
        self,
        target_did: str,
        scope: Optional[str] = None,
        max_depth: int = 5
    ) -> Dict[str, Any]:
        """
        Find trust path to another agent.

        Returns path info including trust_score (decays with hops).
        """
        params = {
            "source_did": self.did,
            "target_did": target_did,
            "max_depth": max_depth
        }
        if scope:
            params["scope"] = scope

        response = self._session.get(f"{self.service_url}/trust-path", params=params)

        if response.status_code != 200:
            raise AIPError(f"Trust path lookup failed: {response.text}")

        return response.json()

    def get_certificate(self, vouch_id: str) -> Dict[str, Any]:
        """Get a portable vouch certificate for offline verification."""
        response = self._session.get(f"{self.service_url}/vouch/certificate/{vouch_id}")

        if response.status_code != 200:
            raise AIPError(f"Certificate fetch failed: {response.text}")

        return response.json()

    def get_trust(self, did: str, scope: Optional[str] = None) -> Dict[str, Any]:
        """
        Quick trust lookup for a DID.

        Returns:
            - registered: whether DID exists
            - vouched_by: list of DIDs that vouch for them
            - scopes: what scopes they're trusted for
            - vouch_count: total active vouches

        Example:
            trust = client.get_trust("did:aip:abc123")
            if trust["vouch_count"] > 0:
                print(f"Vouched by: {trust['vouched_by']}")
        """
        params = {}
        if scope:
            params["scope"] = scope

        response = self._session.get(f"{self.service_url}/trust/{did}", params=params)

        if response.status_code != 200:
            raise AIPError(f"Trust lookup failed: {response.text}")

        return response.json()

    def is_trusted(self, did: str, scope: Optional[str] = None) -> bool:
        """
        Simple check: does this DID have any vouches?

        Args:
            did: DID to check
            scope: Optional scope filter

        Returns:
            True if DID is registered and has at least one vouch
        """
        trust = self.get_trust(did, scope)
        return trust.get("registered", False) and trust.get("vouch_count", 0) > 0


    def get_profile(self, did: str) -> Dict[str, Any]:
        """Get an agent's public profile."""
        response = self._session.get(f"{self.service_url}/agent/{did}/profile")
        if response.status_code != 200:
            raise AIPError(f"Profile lookup failed: {response.text}")
        return response.json()

    def update_profile(self, **fields) -> Dict[str, Any]:
        """Update your own profile. Requires challenge-response auth.

        Args:
            display_name: Display name
            bio: Short bio (max 500 chars)
            avatar_url: URL to avatar image
            website: Website URL
            tags: List of tags (max 10)

        Returns:
            Updated profile dict
        """
        # Get a challenge
        challenge = self.get_challenge(self.did)
        signature = self.sign_challenge(challenge)

        body = {
            "did": self.did,
            "challenge": challenge,
            "signature": signature,
        }
        for field in ("display_name", "bio", "avatar_url", "website", "tags"):
            if field in fields:
                body[field] = fields[field]

        response = self._session.put(
            f"{self.service_url}/agent/{self.did}/profile",
            json=body,
        )
        if response.status_code != 200:
            raise AIPError(f"Profile update failed: {response.text}")
        return response.json()


class AIPError(Exception):
    """Error from AIP operations."""
    pass


# Convenience functions
def register(platform: str, platform_id: str) -> AIPClient:
    """Register a new agent."""
    return AIPClient.register(platform, platform_id)


def load(path: str) -> AIPClient:
    """Load credentials from file."""
    return AIPClient.from_file(path)
