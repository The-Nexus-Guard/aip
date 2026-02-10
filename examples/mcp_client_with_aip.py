#!/usr/bin/env python3
"""
MCP Client with AIP Identity

Demonstrates how to add AIP identity verification to MCP client connections.
This is a proof-of-concept showing how AIP can fill the agent identity gap in MCP.

Usage:
    # First, register with AIP to get your identity
    curl -X POST https://aip-service.fly.dev/register/easy \
        -H "Content-Type: application/json" \
        -d '{"platform": "mcp", "username": "my-agent"}'

    # Save the returned private_key to a file

    # Then use this client
    python mcp_client_with_aip.py --did "did:aip:xxx" --key-file "my_key.txt"
"""

import json
import hashlib
import base64
import argparse
from typing import Optional, Dict, Any

# For Ed25519 signing (using pure Python fallback if nacl not available)
try:
    from nacl.signing import SigningKey, VerifyKey
    from nacl.encoding import Base64Encoder
    NACL_AVAILABLE = True
except ImportError:
    NACL_AVAILABLE = False
    print("Warning: PyNaCl not available. Using stub implementation.")


class AIPIdentity:
    """Agent identity based on AIP (Agent Identity Protocol)."""

    def __init__(self, did: str, private_key_b64: str):
        self.did = did
        self.private_key_b64 = private_key_b64

        if NACL_AVAILABLE:
            # Decode and create signing key
            private_key_bytes = base64.b64decode(private_key_b64)
            self.signing_key = SigningKey(private_key_bytes[:32])  # Ed25519 seed is 32 bytes
            self.public_key = self.signing_key.verify_key
            self.public_key_b64 = base64.b64encode(
                bytes(self.public_key)
            ).decode('utf-8')
        else:
            # Stub for demonstration
            self.public_key_b64 = "stub-public-key"

    def sign_challenge(self, challenge: str) -> str:
        """Sign a challenge to prove identity."""
        if NACL_AVAILABLE:
            signed = self.signing_key.sign(challenge.encode('utf-8'))
            return base64.b64encode(signed.signature).decode('utf-8')
        else:
            # Stub - in real implementation, would sign with private key
            return base64.b64encode(
                hashlib.sha256(f"{self.did}:{challenge}".encode()).digest()
            ).decode('utf-8')

    def get_client_info(self) -> Dict[str, Any]:
        """Get AIP info to include in MCP client initialization."""
        return {
            "did": self.did,
            "public_key": self.public_key_b64
        }


class AIPMCPClient:
    """
    MCP Client enhanced with AIP identity.

    This wraps standard MCP client functionality and adds:
    1. Identity declaration in initialization
    2. Challenge-response verification support
    3. Trust checking for servers
    """

    def __init__(self, identity: AIPIdentity, aip_service_url: str = "https://aip-service.fly.dev"):
        self.identity = identity
        self.aip_service_url = aip_service_url
        self.verified = False

    def build_initialize_params(self, client_name: str, client_version: str) -> Dict[str, Any]:
        """
        Build MCP initialize parameters with AIP identity included.

        This extends the standard MCP initialize request to include
        cryptographic identity information.
        """
        return {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "roots": {"listChanged": True},
                "sampling": {}
            },
            "clientInfo": {
                "name": client_name,
                "version": client_version,
                # AIP extension - identity information
                "aip": self.identity.get_client_info()
            }
        }

    def handle_challenge(self, challenge: str) -> Dict[str, str]:
        """
        Handle a challenge from an AIP-aware MCP server.

        If the server wants to verify the client's identity,
        it sends a challenge. We sign it to prove we control the DID.
        """
        signature = self.identity.sign_challenge(challenge)
        return {
            "did": self.identity.did,
            "signature": signature
        }

    def check_server_trust(self, server_did: str) -> Dict[str, Any]:
        """
        Check if we have a trust path to an MCP server.

        Before connecting to an unknown server, agents can check
        if anyone they trust has vouched for it.
        """
        import urllib.request
        import urllib.parse

        url = f"{self.aip_service_url}/trust-graph?source_did={urllib.parse.quote(self.identity.did)}&target_did={urllib.parse.quote(server_did)}"

        try:
            with urllib.request.urlopen(url, timeout=5) as response:
                data = json.loads(response.read().decode('utf-8'))
                return {
                    "trusted": data.get("path_exists", False),
                    "path_length": data.get("path_length"),
                    "trust_level": data.get("trust_level")
                }
        except Exception as e:
            return {
                "trusted": False,
                "error": str(e)
            }


def demo():
    """Demonstrate AIP-enhanced MCP client."""

    print("=== AIP + MCP Integration Demo ===\n")

    # Example identity (in real usage, load from saved credentials)
    demo_did = "did:aip:demo123"
    demo_key = base64.b64encode(b"x" * 32).decode('utf-8')  # Stub key

    # Create identity
    identity = AIPIdentity(demo_did, demo_key)
    print(f"Agent DID: {identity.did}")
    print(f"Public Key: {identity.public_key_b64[:20]}...")

    # Create AIP-enhanced MCP client
    client = AIPMCPClient(identity)

    # Build initialize params
    init_params = client.build_initialize_params(
        client_name="demo-agent",
        client_version="1.0.0"
    )

    print("\n--- MCP Initialize Request (with AIP) ---")
    print(json.dumps(init_params, indent=2))

    # Demonstrate challenge handling
    print("\n--- Challenge-Response Demo ---")
    test_challenge = "server-nonce-xyz123"
    response = client.handle_challenge(test_challenge)
    print(f"Challenge: {test_challenge}")
    print(f"Response: {json.dumps(response, indent=2)}")

    print("\n=== Integration Points ===")
    print("""
1. INITIALIZATION: Include AIP identity in clientInfo
   - Server sees agent's DID and public key
   - Enables server-side verification

2. VERIFICATION: Respond to challenges
   - Server sends random nonce
   - Client signs with private key
   - Server verifies signature

3. TRUST: Check server reputation before connecting
   - Query AIP trust graph
   - Only connect to vouched servers
   - Build trust network over time

4. AUDIT: Log all connections with DIDs
   - Who connected to what, when
   - Cryptographic proof of interactions
""")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MCP Client with AIP Identity")
    parser.add_argument("--did", help="Your AIP DID")
    parser.add_argument("--key-file", help="Path to private key file")
    parser.add_argument("--demo", action="store_true", help="Run demo mode")

    args = parser.parse_args()

    if args.demo or (not args.did):
        demo()
    else:
        # Real usage with provided credentials
        with open(args.key_file, 'r') as f:
            private_key = f.read().strip()

        identity = AIPIdentity(args.did, private_key)
        client = AIPMCPClient(identity)

        init_params = client.build_initialize_params(
            client_name="my-agent",
            client_version="1.0.0"
        )

        print("MCP Initialize params with AIP identity:")
        print(json.dumps(init_params, indent=2))
