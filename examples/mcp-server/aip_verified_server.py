#!/usr/bin/env python3
"""
MCP Server with AIP Identity Verification

A proof-of-concept MCP server that uses AIP (Agent Identity Protocol) to:
1. Verify client identity before allowing tool execution
2. Log all tool calls with verified DIDs for audit trail
3. Apply trust-based access control

This demonstrates how AIP fills the agent identity gap in MCP.

Usage:
    pip install mcp httpx pynacl
    python aip_verified_server.py

    # Connect with an AIP-enabled client
    # Client must provide X-AIP-DID header and sign challenges
"""

import asyncio
import json
import secrets
import base64
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field

import httpx

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("aip-mcp-server")

# AIP Service URL
AIP_SERVICE = "https://aip-service.fly.dev"

# Challenge expiration (seconds)
CHALLENGE_EXPIRY = 30


@dataclass
class VerifiedSession:
    """Represents a verified agent session."""
    did: str
    public_key: str
    verified_at: datetime
    trust_scopes: List[str] = field(default_factory=list)


@dataclass
class PendingChallenge:
    """Tracks pending verification challenges."""
    nonce: str
    did: str
    created_at: datetime
    expires_at: datetime


class AIPVerifier:
    """
    Handles AIP identity verification for MCP connections.

    Flow:
    1. Client connects and declares DID
    2. Server creates challenge (random nonce)
    3. Client signs challenge with private key
    4. Server verifies signature against AIP service
    5. Session is marked as verified
    """

    def __init__(self, aip_service_url: str = AIP_SERVICE):
        self.aip_service_url = aip_service_url
        self.pending_challenges: Dict[str, PendingChallenge] = {}
        self.verified_sessions: Dict[str, VerifiedSession] = {}
        self.http_client = httpx.AsyncClient(timeout=10.0)

    async def lookup_did(self, did: str) -> Optional[Dict[str, Any]]:
        """Look up a DID in the AIP registry."""
        try:
            response = await self.http_client.get(
                f"{self.aip_service_url}/lookup/{did}"
            )
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            logger.error(f"DID lookup failed: {e}")
            return None

    def create_challenge(self, did: str) -> str:
        """Create a verification challenge for a DID."""
        nonce = secrets.token_hex(32)
        now = datetime.utcnow()

        self.pending_challenges[nonce] = PendingChallenge(
            nonce=nonce,
            did=did,
            created_at=now,
            expires_at=now + timedelta(seconds=CHALLENGE_EXPIRY)
        )

        return nonce

    async def verify_challenge(self, did: str, nonce: str, signature: str) -> bool:
        """
        Verify a signed challenge through AIP service.

        Returns True if signature is valid and matches the DID's public key.
        """
        # Check if challenge exists and isn't expired
        challenge = self.pending_challenges.get(nonce)
        if not challenge:
            logger.warning(f"Challenge not found: {nonce[:16]}...")
            return False

        if challenge.did != did:
            logger.warning(f"Challenge DID mismatch: expected {challenge.did}, got {did}")
            return False

        if datetime.utcnow() > challenge.expires_at:
            logger.warning(f"Challenge expired for {did}")
            del self.pending_challenges[nonce]
            return False

        # Verify through AIP service
        try:
            response = await self.http_client.post(
                f"{self.aip_service_url}/verify-challenge",
                json={
                    "did": did,
                    "challenge": nonce,
                    "signature": signature
                }
            )

            result = response.json()

            if result.get("verified"):
                # Mark session as verified
                did_info = await self.lookup_did(did)
                self.verified_sessions[did] = VerifiedSession(
                    did=did,
                    public_key=did_info.get("public_key", "") if did_info else "",
                    verified_at=datetime.utcnow()
                )

                # Clean up challenge
                del self.pending_challenges[nonce]

                logger.info(f"Session verified for {did}")
                return True
            else:
                logger.warning(f"Verification failed for {did}: {result.get('message')}")
                return False

        except Exception as e:
            logger.error(f"Challenge verification failed: {e}")
            return False

    def is_verified(self, did: str) -> bool:
        """Check if a DID has a verified session."""
        return did in self.verified_sessions

    async def check_trust(self, did: str, required_scope: str) -> bool:
        """
        Check if a DID has trust vouches for a required scope.

        Used for access control on sensitive operations.
        """
        try:
            response = await self.http_client.get(
                f"{self.aip_service_url}/trust-graph",
                params={"did": did}
            )

            if response.status_code != 200:
                return False

            data = response.json()
            vouches = data.get("vouched_by", [])

            for vouch in vouches:
                if vouch.get("scope") == required_scope:
                    return True

            return False

        except Exception as e:
            logger.error(f"Trust check failed: {e}")
            return False

    async def close(self):
        """Clean up resources."""
        await self.http_client.aclose()


class AIPMCPServer:
    """
    MCP Server enhanced with AIP identity verification.

    Features:
    - Verifies client identity before sensitive operations
    - Logs all tool calls with verified DIDs
    - Applies trust-based access control
    """

    def __init__(self, name: str = "aip-secured-mcp-server", version: str = "1.0.0"):
        self.name = name
        self.version = version
        self.verifier = AIPVerifier()
        self.audit_log: List[Dict[str, Any]] = []

        # Define which tools require verification
        self.sensitive_tools = {
            "execute_code": "CODE_SIGNING",
            "transfer_funds": "FINANCIAL",
            "modify_config": "GENERAL"
        }

    async def handle_initialize(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle MCP initialize request.

        If client provides AIP identity in clientInfo, start verification.
        """
        client_info = params.get("clientInfo", {})
        aip_info = client_info.get("aip", {})

        response = {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {"listChanged": False}
            },
            "serverInfo": {
                "name": self.name,
                "version": self.version,
                "aip": {
                    "identity_required": True,
                    "verification_endpoint": "/aip/verify"
                }
            }
        }

        # If client declared AIP identity, create challenge
        if aip_info.get("did"):
            challenge = self.verifier.create_challenge(aip_info["did"])
            response["serverInfo"]["aip"]["challenge"] = challenge
            response["serverInfo"]["aip"]["challenge_expires_in"] = CHALLENGE_EXPIRY
            logger.info(f"Challenge created for {aip_info['did']}")

        return response

    async def handle_verify(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle AIP verification request (custom extension).

        Client sends signed challenge to prove identity.
        """
        did = params.get("did")
        challenge = params.get("challenge")
        signature = params.get("signature")

        if not all([did, challenge, signature]):
            return {"verified": False, "error": "Missing required fields"}

        verified = await self.verifier.verify_challenge(did, challenge, signature)

        return {
            "verified": verified,
            "did": did if verified else None,
            "message": "Identity verified" if verified else "Verification failed"
        }

    async def handle_tool_call(self, tool_name: str, args: Dict[str, Any], caller_did: Optional[str] = None) -> Dict[str, Any]:
        """
        Handle a tool call with identity verification.

        For sensitive tools, requires verified identity and appropriate trust.
        """
        # Log the call
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "tool": tool_name,
            "caller_did": caller_did,
            "verified": self.verifier.is_verified(caller_did) if caller_did else False
        }

        # Check if tool requires verification
        required_scope = self.sensitive_tools.get(tool_name)

        if required_scope:
            # Tool is sensitive - require verified identity
            if not caller_did:
                log_entry["result"] = "denied_no_identity"
                self.audit_log.append(log_entry)
                return {
                    "error": f"Tool '{tool_name}' requires AIP identity verification",
                    "code": "IDENTITY_REQUIRED"
                }

            if not self.verifier.is_verified(caller_did):
                log_entry["result"] = "denied_not_verified"
                self.audit_log.append(log_entry)
                return {
                    "error": f"Identity not verified. Complete challenge-response first.",
                    "code": "NOT_VERIFIED"
                }

            # Check trust scope
            has_trust = await self.verifier.check_trust(caller_did, required_scope)
            if not has_trust:
                log_entry["result"] = f"denied_no_trust_{required_scope}"
                self.audit_log.append(log_entry)
                return {
                    "error": f"Tool '{tool_name}' requires '{required_scope}' trust scope",
                    "code": "INSUFFICIENT_TRUST"
                }

        # Execute tool (stub implementation)
        result = await self._execute_tool(tool_name, args)
        log_entry["result"] = "success"
        self.audit_log.append(log_entry)

        return result

    async def _execute_tool(self, tool_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a tool (stub implementation for demo)."""
        return {
            "tool": tool_name,
            "result": f"Executed {tool_name} with args: {args}",
            "timestamp": datetime.utcnow().isoformat()
        }

    def get_audit_log(self) -> List[Dict[str, Any]]:
        """Get the audit log of all tool calls."""
        return self.audit_log

    async def close(self):
        """Clean up resources."""
        await self.verifier.close()


async def demo():
    """Demonstrate the AIP-verified MCP server."""
    print("=" * 60)
    print("AIP-Verified MCP Server Demo")
    print("=" * 60)

    server = AIPMCPServer()

    # Simulate client connection
    print("\n1. Client connects with AIP identity")
    init_response = await server.handle_initialize({
        "protocolVersion": "2024-11-05",
        "clientInfo": {
            "name": "demo-agent",
            "version": "1.0.0",
            "aip": {
                "did": "did:aip:demo123",
                "public_key": "demo-public-key"
            }
        }
    })
    print(f"   Server response: Challenge created")
    print(f"   Challenge: {init_response['serverInfo']['aip'].get('challenge', 'N/A')[:32]}...")

    # Simulate tool call without verification
    print("\n2. Client tries sensitive tool WITHOUT verification")
    result = await server.handle_tool_call(
        "execute_code",
        {"code": "print('hello')"},
        caller_did="did:aip:demo123"
    )
    print(f"   Result: {result.get('error', result)}")

    # Simulate verification (would normally use real signature)
    print("\n3. In production, client would sign challenge and verify")
    print("   (Skipping actual signature for demo)")

    # Show what happens after verification
    print("\n4. After verification, sensitive tools check trust scopes")
    print("   - execute_code requires CODE_SIGNING trust")
    print("   - transfer_funds requires FINANCIAL trust")
    print("   - modify_config requires GENERAL trust")

    # Show audit log
    print("\n5. Audit log records all attempts")
    for entry in server.get_audit_log():
        print(f"   [{entry['timestamp'][:19]}] {entry['tool']}: {entry['result']}")

    print("\n" + "=" * 60)
    print("Key Security Properties:")
    print("=" * 60)
    print("""
    ✓ Identity verification before sensitive operations
    ✓ Cryptographic proof of caller identity (Ed25519)
    ✓ Trust-based access control (vouch scopes)
    ✓ Complete audit trail with DIDs
    ✓ Challenge-response prevents replay attacks
    """)

    await server.close()


if __name__ == "__main__":
    asyncio.run(demo())
