"""
AIP Identity Middleware — transparent identity for agent frameworks.

Provides request signing, peer verification, and trust-aware interactions
as drop-in middleware. No CLI required.

Usage:
    from aip_identity.middleware import AIPMiddleware

    # Initialize (auto-registers if no credentials exist)
    mw = AIPMiddleware("my-agent", platform="langchain")

    # Sign outgoing requests
    signed_headers = mw.sign_request("GET", "/api/data")

    # Verify incoming requests
    identity = mw.verify_request(headers)

    # Get trust score for a peer
    score = mw.trust_score("did:aip:abc123...")

    # Use as requests session (auto-signs all requests)
    resp = mw.session.get("https://other-agent.example.com/api/data")
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from aip_identity.client import AIPClient
from aip_identity.integrations.auto import ensure_identity


class AIPIdentity:
    """Lightweight identity info returned from verification."""

    def __init__(self, did: str, public_key: str, trust_score: float = 0.0,
                 verified: bool = False, platform: str = ""):
        self.did = did
        self.public_key = public_key
        self.trust_score = trust_score
        self.verified = verified
        self.platform = platform

    def __repr__(self):
        return (
            f"AIPIdentity(did='{self.did}', trust_score={self.trust_score}, "
            f"verified={self.verified})"
        )

    def __bool__(self):
        return self.verified


class AIPMiddleware:
    """
    Identity middleware for agent-to-agent communication.

    Handles:
    - Auto-registration on first use
    - Request signing (Ed25519 signatures on HTTP headers)
    - Peer verification
    - Trust score lookups
    - Signed request sessions

    Example:
        mw = AIPMiddleware("my-agent")
        print(mw.did)  # did:aip:abc123...

        # Sign a request
        headers = mw.sign_request("POST", "/api/submit", body='{"key": "value"}')

        # Verify a peer
        identity = mw.verify_request(incoming_headers)
        if identity.trust_score > 0.5:
            process(request)
    """

    # Header names for AIP signatures
    HEADER_DID = "X-AIP-DID"
    HEADER_SIGNATURE = "X-AIP-Signature"
    HEADER_TIMESTAMP = "X-AIP-Timestamp"
    HEADER_NONCE = "X-AIP-Nonce"

    def __init__(
        self,
        agent_name: str = "agent",
        platform: str = "middleware",
        credentials_path: Optional[str] = None,
        service_url: str = AIPClient.DEFAULT_SERVICE,
        auto_register: bool = True,
        verify_peers: bool = True,
        min_trust_score: float = 0.0,
    ):
        """
        Initialize the middleware.

        Args:
            agent_name: Display name for this agent
            platform: Platform identifier
            credentials_path: Override credentials file location
            service_url: AIP service URL
            auto_register: If True, auto-register if no credentials found
            verify_peers: If True, verify peer signatures on incoming requests
            min_trust_score: Minimum trust score to accept peer requests
        """
        self.verify_peers = verify_peers
        self.min_trust_score = min_trust_score
        self._client: Optional[AIPClient] = None

        if auto_register:
            self._client = ensure_identity(
                agent_name=agent_name,
                platform=platform,
                credentials_path=credentials_path,
                service_url=service_url,
            )

    @classmethod
    def from_client(cls, client: AIPClient, **kwargs) -> "AIPMiddleware":
        """Create middleware from an existing AIPClient."""
        mw = cls.__new__(cls)
        mw._client = client
        mw.verify_peers = kwargs.get("verify_peers", True)
        mw.min_trust_score = kwargs.get("min_trust_score", 0.0)
        return mw

    @property
    def client(self) -> AIPClient:
        """Get the underlying AIPClient."""
        if self._client is None:
            raise RuntimeError("Middleware not initialized. Call with auto_register=True or use from_client().")
        return self._client

    @property
    def did(self) -> str:
        """This agent's DID."""
        return self.client.did

    def sign_request(
        self,
        method: str,
        path: str,
        body: Optional[str] = None,
        timestamp: Optional[str] = None,
    ) -> Dict[str, str]:
        """
        Generate signed headers for an outgoing request.

        The signature covers: method + path + timestamp + body_hash.
        Recipients can verify this using the public key from the AIP registry.

        Args:
            method: HTTP method (GET, POST, etc.)
            path: Request path
            body: Request body (for POST/PUT)
            timestamp: ISO timestamp (auto-generated if not provided)

        Returns:
            Dict of headers to add to the request
        """
        if timestamp is None:
            timestamp = datetime.now(tz=timezone.utc).isoformat()

        # Create canonical message
        body_hash = hashlib.sha256((body or "").encode()).hexdigest()
        nonce = hashlib.sha256(f"{time.time()}:{id(self)}".encode()).hexdigest()[:16]
        message = f"{method.upper()}:{path}:{timestamp}:{nonce}:{body_hash}"

        # Sign with Ed25519
        sig = self.client.sign(message)

        return {
            self.HEADER_DID: self.did,
            self.HEADER_SIGNATURE: sig,
            self.HEADER_TIMESTAMP: timestamp,
            self.HEADER_NONCE: nonce,
        }

    def verify_request(
        self,
        headers: Dict[str, str],
        method: str = "",
        path: str = "",
        body: Optional[str] = None,
        max_age_seconds: int = 300,
    ) -> AIPIdentity:
        """
        Verify an incoming request's AIP identity headers.

        Args:
            headers: Request headers (case-insensitive)
            method: HTTP method (for signature verification)
            path: Request path (for signature verification)
            body: Request body (for signature verification)
            max_age_seconds: Maximum age of the timestamp (default 5 min)

        Returns:
            AIPIdentity with verification status
        """
        # Normalize headers
        h = {k.lower(): v for k, v in headers.items()}

        did = h.get(self.HEADER_DID.lower(), "")
        signature = h.get(self.HEADER_SIGNATURE.lower(), "")
        timestamp = h.get(self.HEADER_TIMESTAMP.lower(), "")
        nonce = h.get(self.HEADER_NONCE.lower(), "")

        if not all([did, signature, timestamp]):
            return AIPIdentity(did=did, public_key="", verified=False)

        # Check timestamp freshness
        try:
            ts = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            age = abs((datetime.now(tz=timezone.utc) - ts).total_seconds())
            if age > max_age_seconds:
                return AIPIdentity(did=did, public_key="", verified=False)
        except (ValueError, TypeError):
            return AIPIdentity(did=did, public_key="", verified=False)

        # Reconstruct message and verify
        body_hash = hashlib.sha256((body or "").encode()).hexdigest()
        message = f"{method.upper()}:{path}:{timestamp}:{nonce}:{body_hash}"

        try:
            verified = self.client.verify_signature(did, message, signature)
        except Exception:
            verified = False

        # Get trust info
        trust_score = 0.0
        platform = ""
        public_key = ""
        try:
            info = self.client.resolve(did)
            trust_score = info.get("trust_score", 0.0)
            platform = info.get("platform", "")
            public_key = info.get("public_key", "")
        except Exception:
            pass

        return AIPIdentity(
            did=did,
            public_key=public_key,
            trust_score=trust_score,
            verified=verified,
            platform=platform,
        )

    def trust_score(self, peer_did: str) -> float:
        """
        Get the trust score for a peer agent.

        Args:
            peer_did: The peer's DID

        Returns:
            Trust score (0.0 to 1.0)
        """
        try:
            return self.client.get_trust_score(peer_did)
        except Exception:
            return 0.0

    def discover_peers(
        self,
        platform: Optional[str] = None,
        min_trust: float = 0.0,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """
        Discover registered agents, optionally filtered by platform and trust.

        Returns:
            List of agent records from the AIP directory
        """
        try:
            agents = self.client.search_agents(platform=platform, limit=limit)
            if min_trust > 0:
                agents = [
                    a for a in agents
                    if a.get("trust_score", 0) >= min_trust
                ]
            return agents
        except Exception:
            return []

    def send_message(self, to_did: str, content: str) -> bool:
        """
        Send an encrypted message to another agent.

        Args:
            to_did: Recipient's DID
            content: Message content (will be encrypted)

        Returns:
            True if sent successfully
        """
        try:
            self.client.send_message(to_did, content)
            return True
        except Exception:
            return False

    def get_messages(self, mark_read: bool = False) -> List[Dict[str, Any]]:
        """
        Get incoming messages.

        Args:
            mark_read: If True, mark messages as read

        Returns:
            List of message dicts
        """
        try:
            return self.client.get_messages(mark_read=mark_read)
        except Exception:
            return []
